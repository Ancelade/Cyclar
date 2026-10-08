//! Qualified Linux/X11 backend. Other desktop APIs require separate native
//! adapters and are deliberately not represented as working here.

use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex, OnceLock,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use cyclar_transfer::{FileOffer, FileSender, ResumeProof, TransferMessage};
use jpeg_decoder::{Decoder, PixelFormat};
use jpeg_encoder::{ColorType, Encoder};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt as _, CreateGCAux, CreateWindowAux, EventMask, ImageFormat, ImageOrder,
    PropMode, WindowClass,
};
use x11rb::protocol::{xtest::ConnectionExt as _, Event};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::COPY_DEPTH_FROM_PARENT;

use crate::packet::Packet;
use crate::secure::{SecureReader, SecureWriter};

const MAX_WIDTH: u16 = 4096;
const MAX_HEIGHT: u16 = 2160;
const FILE_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct OutgoingFile {
    alias: u64,
    path: PathBuf,
    offer: FileOffer,
}

static OUTGOING: OnceLock<Mutex<HashMap<(u64, PathBuf), FileOffer>>> = OnceLock::new();

/// Inspect metadata only. Reuse a transfer ID across a reconnect in this
/// process so the host can request a verified prefix from its temporary file.
pub fn prepare_outgoing(alias: u64, path: PathBuf) -> Result<OutgoingFile> {
    let candidate = FileOffer::from_path(&path)?;
    let cache = OUTGOING.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache
        .lock()
        .map_err(|_| anyhow!("outgoing transfer state unavailable"))?;
    let offer = cache
        .entry((alias, path.clone()))
        .or_insert_with(|| candidate.clone());
    if offer.file_name != candidate.file_name || offer.size != candidate.size {
        *offer = candidate;
    }
    Ok(OutgoingFile {
        alias,
        path,
        offer: offer.clone(),
    })
}

fn forget_outgoing(outgoing: &OutgoingFile) {
    if let Some(cache) = OUTGOING.get() {
        if let Ok(mut cache) = cache.lock() {
            let key = (outgoing.alias, outgoing.path.clone());
            if cache
                .get(&key)
                .is_some_and(|offer| offer.transfer_id == outgoing.offer.transfer_id)
            {
                cache.remove(&key);
            }
        }
    }
}

fn validate_layout(conn: &RustConnection, screen_index: usize) -> Result<(u32, u8)> {
    let setup = conn.setup();
    let screen = &setup.roots[screen_index];
    let format_ok = setup
        .pixmap_formats
        .iter()
        .any(|format| format.depth == screen.root_depth && format.bits_per_pixel == 32);
    let visual_ok = screen
        .allowed_depths
        .iter()
        .flat_map(|depth| &depth.visuals)
        .find(|visual| visual.visual_id == screen.root_visual)
        .is_some_and(|visual| {
            visual.red_mask == 0x00ff0000
                && visual.green_mask == 0x0000ff00
                && visual.blue_mask == 0x000000ff
        });
    if screen.root_depth != 24
        || setup.image_byte_order != ImageOrder::LSB_FIRST
        || !format_ok
        || !visual_ok
    {
        bail!("X11 visual unsupported: requires 24-bit TrueColor with 32-bit little-endian pixels");
    }
    Ok((screen.root, screen.root_depth))
}

pub fn check_available() -> Result<()> {
    let (conn, screen_index) =
        x11rb::connect(None).context("X11 unavailable; set DISPLAY and grant screen access")?;
    validate_layout(&conn, screen_index)?;
    Ok(())
}

pub struct Capture {
    conn: RustConnection,
    root: u32,
}

impl Capture {
    pub fn new() -> Result<Self> {
        let (conn, screen_index) =
            x11rb::connect(None).context("X11 screen capture unavailable")?;
        let (root, _) = validate_layout(&conn, screen_index)?;
        Ok(Self { conn, root })
    }

    pub fn frame(&self) -> Result<Packet> {
        let geometry = self.conn.get_geometry(self.root)?.reply()?;
        let (width, height) = (geometry.width, geometry.height);
        if width == 0 || height == 0 || width > MAX_WIDTH || height > MAX_HEIGHT {
            bail!("screen dimensions exceed the qualified capture range (4096x2160)");
        }
        let image = self
            .conn
            .get_image(
                ImageFormat::Z_PIXMAP,
                self.root,
                0,
                0,
                width,
                height,
                u32::MAX,
            )?
            .reply()?;
        let required = width as usize * height as usize * 4;
        if image.data.len() < required {
            bail!("X11 returned a truncated frame");
        }
        let mut rgb = Vec::with_capacity(width as usize * height as usize * 3);
        for pixel in image.data[..required].chunks_exact(4) {
            rgb.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
        }
        let mut jpeg = Vec::new();
        Encoder::new(&mut jpeg, 70)
            .encode(&rgb, width, height, ColorType::Rgb)
            .context("JPEG encoding failed")?;
        Ok(Packet::Video {
            width,
            height,
            jpeg,
        })
    }
}

pub struct Input {
    conn: RustConnection,
    root: u32,
    pressed_keys: HashSet<u8>,
    pressed_buttons: HashSet<u8>,
    min_keycode: u8,
    max_keycode: u8,
}

impl Input {
    pub fn new() -> Result<Self> {
        let (conn, screen_index) = x11rb::connect(None).context("X11 input unavailable")?;
        let (root, _) = validate_layout(&conn, screen_index)?;
        if !conn.query_extension(b"XTEST")?.reply()?.present {
            bail!("XTEST extension unavailable; remote input cannot be enabled");
        }
        let min_keycode = conn.setup().min_keycode;
        let max_keycode = conn.setup().max_keycode;
        Ok(Self {
            conn,
            root,
            pressed_keys: HashSet::new(),
            pressed_buttons: HashSet::new(),
            min_keycode,
            max_keycode,
        })
    }

    pub fn apply(&mut self, packet: Packet) -> Result<()> {
        match packet {
            Packet::Motion { x, y } => {
                let geometry = self.conn.get_geometry(self.root)?.reply()?;
                let x = x.min(geometry.width.saturating_sub(1)).min(i16::MAX as u16) as i16;
                let y = y
                    .min(geometry.height.saturating_sub(1))
                    .min(i16::MAX as u16) as i16;
                self.conn.xtest_fake_input(6, 0, 0, self.root, x, y, 0)?;
            }
            Packet::Button { button, pressed } => {
                if pressed {
                    self.pressed_buttons.insert(button);
                } else {
                    self.pressed_buttons.remove(&button);
                }
                self.conn.xtest_fake_input(
                    if pressed { 4 } else { 5 },
                    button,
                    0,
                    self.root,
                    0,
                    0,
                    0,
                )?;
            }
            Packet::Key { keycode, pressed } => {
                if keycode < self.min_keycode || keycode > self.max_keycode {
                    bail!("remote keycode outside X11 key range");
                }
                if pressed {
                    self.pressed_keys.insert(keycode);
                } else {
                    self.pressed_keys.remove(&keycode);
                }
                self.conn.xtest_fake_input(
                    if pressed { 2 } else { 3 },
                    keycode,
                    0,
                    self.root,
                    0,
                    0,
                    0,
                )?;
            }
            _ => bail!("message is not an input event"),
        }
        self.conn.flush()?;
        Ok(())
    }

    pub fn release_all(&mut self) {
        for keycode in self.pressed_keys.drain() {
            let _ = self
                .conn
                .xtest_fake_input(3, keycode, 0, self.root, 0, 0, 0);
        }
        for button in self.pressed_buttons.drain() {
            let _ = self.conn.xtest_fake_input(5, button, 0, self.root, 0, 0, 0);
        }
        let _ = self.conn.flush();
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        self.release_all();
    }
}

#[derive(Clone)]
struct Frame {
    width: u16,
    height: u16,
    rgb: Vec<u8>,
}

fn decode_frame(width: u16, height: u16, jpeg: Vec<u8>) -> Result<Frame> {
    if width == 0 || width > MAX_WIDTH || height == 0 || height > MAX_HEIGHT {
        bail!("remote frame dimensions out of bounds");
    }
    let mut decoder = Decoder::new(Cursor::new(jpeg));
    decoder.read_info().context("invalid JPEG header")?;
    let info = decoder
        .info()
        .ok_or_else(|| anyhow!("missing JPEG dimensions"))?;
    if info.width != width || info.height != height || info.pixel_format != PixelFormat::RGB24 {
        bail!("JPEG format differs from authenticated frame metadata");
    }
    let rgb = decoder.decode().context("invalid JPEG frame")?;
    if rgb.len() != width as usize * height as usize * 3 {
        bail!("decoded JPEG length mismatch");
    }
    Ok(Frame { width, height, rgb })
}

/// Image bounds inside a resizable viewer window, preserving aspect ratio.
fn fit_rect(
    source_width: u16,
    source_height: u16,
    window_width: u16,
    window_height: u16,
) -> (u16, u16, u16, u16) {
    let scale = (window_width as f64 / source_width as f64)
        .min(window_height as f64 / source_height as f64);
    let width = ((source_width as f64 * scale).round() as u16).clamp(1, window_width);
    let height = ((source_height as f64 * scale).round() as u16).clamp(1, window_height);
    (
        (window_width - width) / 2,
        (window_height - height) / 2,
        width,
        height,
    )
}

fn project_pointer(
    x: i16,
    y: i16,
    source_width: u16,
    source_height: u16,
    window_width: u16,
    window_height: u16,
) -> Option<(u16, u16)> {
    let (left, top, width, height) =
        fit_rect(source_width, source_height, window_width, window_height);
    if x < left as i16 || y < top as i16 || x >= (left + width) as i16 || y >= (top + height) as i16
    {
        return None;
    }
    let remote_x = ((x as u32 - left as u32) * source_width as u32 / width as u32)
        .min(source_width as u32 - 1);
    let remote_y = ((y as u32 - top as u32) * source_height as u32 / height as u32)
        .min(source_height as u32 - 1);
    Some((remote_x as u16, remote_y as u16))
}

fn render(
    conn: &RustConnection,
    window: u32,
    gc: u32,
    depth: u8,
    frame: &Frame,
    window_width: u16,
    window_height: u16,
) -> Result<()> {
    let (left, top, width, height) =
        fit_rect(frame.width, frame.height, window_width, window_height);
    conn.clear_area(false, window, 0, 0, window_width, window_height)?;
    // X11 core requests are often limited to about 256 KiB. Send small scanline
    // strips so a normal 1080p window does not require BIG-REQUESTS.
    let rows_per_request = (160_000 / (width as usize * 4)).max(1) as u16;
    for first_row in (0..height).step_by(rows_per_request as usize) {
        let rows = (height - first_row).min(rows_per_request);
        let mut bgrx = vec![0u8; width as usize * rows as usize * 4];
        for row in 0..rows as usize {
            let source_y = (first_row as usize + row) * frame.height as usize / height as usize;
            for column in 0..width as usize {
                let source_x = column * frame.width as usize / width as usize;
                let source = (source_y * frame.width as usize + source_x) * 3;
                let target = (row * width as usize + column) * 4;
                bgrx[target] = frame.rgb[source + 2];
                bgrx[target + 1] = frame.rgb[source + 1];
                bgrx[target + 2] = frame.rgb[source];
            }
        }
        conn.put_image(
            ImageFormat::Z_PIXMAP,
            window,
            gc,
            width,
            rows,
            left as i16,
            (top + first_row) as i16,
            0,
            depth,
            &bgrx,
        )?;
    }
    conn.flush()?;
    Ok(())
}

pub fn view(
    mut reader: SecureReader,
    writer: Arc<Mutex<SecureWriter>>,
    expires_at: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
    outgoing: Option<OutgoingFile>,
) -> Result<()> {
    let first = Packet::decode(&reader.receive()?)?;
    let Packet::Policy { input_allowed } = first else {
        bail!("host did not send a session policy")
    };
    println!(
        "Session ouverte : {}. Fermez la fenêtre pour terminer.",
        if input_allowed {
            "contrôle activé"
        } else {
            "lecture seule"
        }
    );
    if let Some(file) = &outgoing {
        send(
            &writer,
            Packet::Transfer(TransferMessage::Offer(file.offer.clone())),
        )?;
        println!("Offre de fichier {} envoyée ({} octets). L'hôte doit choisir une destination avant toute lecture du contenu.",
            file.offer.file_name, file.offer.size);
    }
    let (conn, screen_index) = x11rb::connect(None).context("X11 viewer unavailable")?;
    let (root, depth) = validate_layout(&conn, screen_index)?;
    let window = conn.generate_id()?;
    let gc = conn.generate_id()?;
    let mut width = 1100u16;
    let mut height = 700u16;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        window,
        root,
        0,
        0,
        width,
        height,
        0,
        WindowClass::INPUT_OUTPUT,
        0,
        &CreateWindowAux::new()
            .background_pixel(conn.setup().roots[screen_index].black_pixel)
            .event_mask(
                EventMask::EXPOSURE
                    | EventMask::STRUCTURE_NOTIFY
                    | EventMask::POINTER_MOTION
                    | EventMask::BUTTON_PRESS
                    | EventMask::BUTTON_RELEASE
                    | EventMask::KEY_PRESS
                    | EventMask::KEY_RELEASE,
            ),
    )?;
    conn.create_gc(gc, window, &CreateGCAux::new())?;
    let wm_protocols = conn.intern_atom(false, b"WM_PROTOCOLS")?.reply()?.atom;
    let wm_delete = conn.intern_atom(false, b"WM_DELETE_WINDOW")?.reply()?.atom;
    conn.change_property32(
        PropMode::REPLACE,
        window,
        wm_protocols,
        AtomEnum::ATOM,
        &[wm_delete],
    )?;
    conn.change_property8(
        PropMode::REPLACE,
        window,
        AtomEnum::WM_NAME,
        AtomEnum::STRING,
        b"Cyclar - session distante",
    )?;
    conn.map_window(window)?;
    conn.flush()?;

    let (sender, receiver) = mpsc::sync_channel::<Frame>(2);
    let reader_active = active.clone();
    let reader_writer = writer.clone();
    let reader_expiry = expires_at.clone();
    let file_started = Arc::new(AtomicBool::new(false));
    let transfer_active = Arc::new(AtomicBool::new(true));
    let sent_digest: Arc<Mutex<Option<[u8; 32]>>> = Arc::new(Mutex::new(None));
    thread::spawn(move || {
        while reader_active.load(Ordering::Relaxed) {
            match reader.receive().and_then(|bytes| Packet::decode(&bytes)) {
                Ok(Packet::Video {
                    width,
                    height,
                    jpeg,
                }) => match decode_frame(width, height, jpeg) {
                    Ok(frame) => {
                        let _ = sender.try_send(frame);
                    }
                    Err(error) => {
                        eprintln!("Image distante invalide : {error}");
                        break;
                    }
                },
                Ok(Packet::Close) => break,
                Ok(Packet::Transfer(message)) => match message {
                    TransferMessage::Request(proof) => {
                        if let Some(file) = outgoing
                            .as_ref()
                            .filter(|file| file.offer.transfer_id == proof.transfer_id)
                        {
                            if !file_started.swap(true, Ordering::Relaxed) {
                                let file = file.clone();
                                let writer = reader_writer.clone();
                                let active = reader_active.clone();
                                let expiry = reader_expiry.clone();
                                let digest = sent_digest.clone();
                                let transfer_active = transfer_active.clone();
                                thread::spawn(move || {
                                    let result = send_file_chunks(
                                        &file,
                                        &proof,
                                        &writer,
                                        &active,
                                        &expiry,
                                        &transfer_active,
                                        &digest,
                                    );
                                    if let Err(error) = result {
                                        eprintln!("Transfert interrompu : {error}");
                                        let _ = send(
                                            &writer,
                                            Packet::Transfer(TransferMessage::Abort {
                                                transfer_id: file.offer.transfer_id,
                                            }),
                                        );
                                    }
                                });
                            }
                        } else {
                            let _ = send(
                                &reader_writer,
                                Packet::Transfer(TransferMessage::Abort {
                                    transfer_id: proof.transfer_id,
                                }),
                            );
                        }
                    }
                    TransferMessage::Complete {
                        transfer_id,
                        digest,
                    } => {
                        if let Some(file) = outgoing
                            .as_ref()
                            .filter(|file| file.offer.transfer_id == transfer_id)
                        {
                            let expected = sent_digest.lock().ok().and_then(|guard| *guard);
                            match expected {
                                    Some(expected) if expected == digest => println!("Fichier {} reçu et vérifié par l'hôte.", file.offer.file_name),
                                    None => println!("L'hôte confirme que le transfert {transfer_id} avait déjà été achevé ; le contenu local n'a pas été relu."),
                                    _ => eprintln!("Accusé de réception de fichier incohérent."),
                                }
                            if expected.is_none_or(|expected| expected == digest) {
                                forget_outgoing(file);
                            }
                        }
                    }
                    TransferMessage::Abort { transfer_id } => {
                        if outgoing
                            .as_ref()
                            .is_some_and(|file| file.offer.transfer_id == transfer_id)
                        {
                            transfer_active.store(false, Ordering::Relaxed);
                            eprintln!("L'hôte a refusé ou interrompu le transfert {transfer_id}.");
                        }
                    }
                    TransferMessage::Offer(_) | TransferMessage::Chunk(_) => {
                        eprintln!("Message de transfert inattendu côté contrôleur.");
                        break;
                    }
                },
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Session interrompue : {error}");
                    break;
                }
            }
        }
        reader_active.store(false, Ordering::Relaxed);
    });

    let mut frame: Option<Frame> = None;
    let mut dirty = false;
    while active.load(Ordering::Relaxed) && now_seconds() < expires_at.load(Ordering::Relaxed) {
        while let Ok(latest) = receiver.try_recv() {
            frame = Some(latest);
            dirty = true;
        }
        while let Some(event) = conn.poll_for_event()? {
            match event {
                Event::ConfigureNotify(event) => {
                    width = event.width.max(1);
                    height = event.height.max(1);
                    dirty = true;
                }
                Event::Expose(_) => dirty = true,
                Event::ClientMessage(event) if event.data.as_data32()[0] == wm_delete => {
                    active.store(false, Ordering::Relaxed);
                    break;
                }
                Event::MotionNotify(event) if input_allowed => {
                    if let Some(current) = &frame {
                        if let Some((x, y)) = project_pointer(
                            event.event_x,
                            event.event_y,
                            current.width,
                            current.height,
                            width,
                            height,
                        ) {
                            send(&writer, Packet::Motion { x, y })?;
                        }
                    }
                }
                Event::ButtonPress(event) if input_allowed => {
                    if let Some(current) = &frame {
                        if let Some((x, y)) = project_pointer(
                            event.event_x,
                            event.event_y,
                            current.width,
                            current.height,
                            width,
                            height,
                        ) {
                            send(&writer, Packet::Motion { x, y })?;
                            if (1..=5).contains(&event.detail) {
                                send(
                                    &writer,
                                    Packet::Button {
                                        button: event.detail,
                                        pressed: true,
                                    },
                                )?;
                            }
                        }
                    }
                }
                Event::ButtonRelease(event) if input_allowed => {
                    if let Some(current) = &frame {
                        if let Some((x, y)) = project_pointer(
                            event.event_x,
                            event.event_y,
                            current.width,
                            current.height,
                            width,
                            height,
                        ) {
                            send(&writer, Packet::Motion { x, y })?;
                            if (1..=5).contains(&event.detail) {
                                send(
                                    &writer,
                                    Packet::Button {
                                        button: event.detail,
                                        pressed: false,
                                    },
                                )?;
                            }
                        }
                    }
                }
                Event::KeyPress(event) if input_allowed => send(
                    &writer,
                    Packet::Key {
                        keycode: event.detail,
                        pressed: true,
                    },
                )?,
                Event::KeyRelease(event) if input_allowed => send(
                    &writer,
                    Packet::Key {
                        keycode: event.detail,
                        pressed: false,
                    },
                )?,
                _ => {}
            }
        }
        if dirty {
            if let Some(current) = &frame {
                render(&conn, window, gc, depth, current, width, height)?;
            }
            dirty = false;
        }
        thread::sleep(Duration::from_millis(30));
    }
    active.store(false, Ordering::Relaxed);
    let _ = send(&writer, Packet::Close);
    if now_seconds() >= expires_at.load(Ordering::Relaxed) {
        println!("Le bail de session a expiré.");
    }
    Ok(())
}

fn send(writer: &Arc<Mutex<SecureWriter>>, packet: Packet) -> Result<()> {
    writer
        .lock()
        .map_err(|_| anyhow!("session writer unavailable"))?
        .send(&packet.encode()?)
}

fn send_file_chunks(
    outgoing: &OutgoingFile,
    proof: &ResumeProof,
    writer: &Arc<Mutex<SecureWriter>>,
    active: &Arc<AtomicBool>,
    expires_at: &Arc<AtomicU64>,
    transfer_active: &Arc<AtomicBool>,
    sent_digest: &Arc<Mutex<Option<[u8; 32]>>>,
) -> Result<()> {
    // FileSender::open is deliberately called only after the host's Request.
    let mut sender = FileSender::open(&outgoing.path, outgoing.offer.clone())?;
    sender.resume_from(proof)?;
    loop {
        if !active.load(Ordering::Relaxed)
            || !transfer_active.load(Ordering::Relaxed)
            || now_seconds() >= expires_at.load(Ordering::Relaxed)
        {
            bail!("session or transfer no longer authorized");
        }
        match sender.read_next_chunk_with_limit(FILE_CHUNK_BYTES)? {
            Some(chunk) => {
                send(writer, Packet::Transfer(TransferMessage::Chunk(chunk)))?;
                thread::yield_now();
            }
            None => break,
        }
    }
    let digest = sender.final_digest()?;
    *sent_digest
        .lock()
        .map_err(|_| anyhow!("transfer state unavailable"))? = Some(digest);
    send(
        writer,
        Packet::Transfer(TransferMessage::Complete {
            transfer_id: outgoing.offer.transfer_id,
            digest,
        }),
    )
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_mapping_respects_letterbox_and_bounds() {
        assert_eq!(fit_rect(3840, 2160, 1920, 1200), (0, 60, 1920, 1080));
        assert_eq!(
            project_pointer(960, 600, 3840, 2160, 1920, 1200),
            Some((1920, 1080))
        );
        assert_eq!(project_pointer(960, 10, 3840, 2160, 1920, 1200), None);
    }
}
