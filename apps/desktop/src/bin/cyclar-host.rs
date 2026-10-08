#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "cyclar-host",
    about = "Hôte léger Cyclar (réception uniquement)"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
    #[arg(long, default_value = "0.0.0.0:7420")]
    listen: SocketAddr,
    /// Adresse TCP atteignable par le contrôleur, sous forme IP:port.
    #[arg(long)]
    advertise: Option<String>,
    #[arg(long)]
    state: Option<PathBuf>,
    #[arg(long, default_value = "Poste Cyclar")]
    name: String,
    /// Afficher l'écran mais refuser toute injection clavier/souris.
    #[arg(long)]
    view_only: bool,
    /// Accepter des offres de fichiers après choix local de la destination.
    #[arg(long)]
    allow_files: bool,
    /// Ne publie aucun port direct ; relie les sessions par WSS au central.
    #[arg(long)]
    relay_only: bool,
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    use std::io;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    use cyclar_desktop::host::{self, HostOptions};

    let args = Args::parse();
    let mut host = host::start(HostOptions {
        server_url: args.server,
        listen: args.listen,
        advertise: args.advertise,
        state_path: args
            .state
            .unwrap_or_else(cyclar_desktop::identity::default_state_path),
        name: args.name,
        view_only: args.view_only,
        allow_files: args.allow_files,
        relay_only: args.relay_only,
    })?;
    let stop = host.shutdown_flag();
    let signal_stop = stop.clone();
    ctrlc::set_handler(move || signal_stop.store(true, Ordering::Relaxed))?;
    println!("Commandes locales : secret, rotate, set-password, clear-password, sessions, kick <session>, files, approve <transfert> <dossier>, quit");
    let stdin = io::stdin();
    while !stop.load(Ordering::Relaxed) {
        let mut command = String::new();
        match stdin.read_line(&mut command) {
            Ok(0) => {
                while !stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                }
                break;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        let mut words = command.split_whitespace();
        match words.next() {
                Some("quit" | "q") => stop.store(true, Ordering::Relaxed),
                Some("secret") => {
                    if let Err(error) = host.identity.show_secret_on_tty() {
                        eprintln!("Affichage local impossible : {error}");
                    }
                }
                Some("rotate") => match host.rotate_temporary_password() {
                    Ok(()) => println!("Le serveur a confirmé la rotation du mot de passe temporaire."),
                    Err(error) => eprintln!("Rotation impossible : {error}"),
                },
                Some("set-password") => {
                    let first = rpassword::prompt_password("Nouveau mot de passe permanent (16-256 octets) : ");
                    let second = rpassword::prompt_password("Confirmez le mot de passe permanent : ");
                    match (first, second) {
                        (Ok(first), Ok(second)) if first == second => {
                            match host.set_permanent_password(Some(&first)) {
                                Ok(()) => println!("Mot de passe permanent confirmé par le serveur."),
                                Err(error) => eprintln!("Mot de passe refusé : {error}"),
                            }
                        }
                        (Ok(_), Ok(_)) => eprintln!("Les deux saisies ne correspondent pas."),
                        _ => eprintln!("Saisie masquée indisponible."),
                    }
                }
                Some("clear-password") => match host.set_permanent_password(None) {
                    Ok(()) => println!("Mot de passe permanent supprimé sur le serveur."),
                    Err(error) => eprintln!("Suppression impossible : {error}"),
                },
                Some("sessions") => {
                    let ids = host.session_ids();
                    if ids.is_empty() {
                        println!("Aucun contrôleur connecté.");
                    }
                    for id in ids {
                        println!("Session active : {id}");
                    }
                }
                Some("files") => {
                    let offers = host.pending_files();
                    if offers.is_empty() { println!("Aucune offre en attente."); }
                    for offer in offers {
                        println!("{} · {} ({} octets) · session {}", offer.transfer_id, offer.file_name, offer.size, offer.session_id);
                    }
                }
                Some("approve") => {
                    let rest = command.trim().strip_prefix("approve").unwrap_or("").trim_start();
                    let parsed = rest.find(char::is_whitespace).and_then(|index| {
                        let id = rest[..index].parse().ok()?;
                        let destination = rest[index..].trim_start();
                        if destination.is_empty() { None } else { Some((id, destination)) }
                    });
                    match parsed {
                        Some((id, destination)) => match host.approve_file(id, std::path::Path::new(destination)) {
                            Ok(()) => println!("Destination approuvée ; transfert {id} demandé au contrôleur."),
                            Err(error) => eprintln!("Approbation impossible : {error}"),
                        },
                        None => println!("Usage : approve <ID transfert> <dossier existant>"),
                    }
                }
                Some("kick") => match words.next().and_then(|id| id.parse().ok()) {
                    Some(id) if host.terminate_session(id) => {
                        println!("Session {id} interrompue localement.")
                    }
                    _ => println!("Session introuvable. Tapez sessions pour voir les ID."),
                },
                _ => println!("Commandes : secret, rotate, set-password, clear-password, sessions, kick <session>, files, approve <transfert> <dossier>, quit"),
            }
    }
    host.stop();
    println!("Hôte Cyclar arrêté.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    let _ = Args::parse();
    anyhow::bail!("Aucun backend de capture natif qualifié pour cet OS. Cette version ne fournit que Linux/X11.")
}
