#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "cyclar-desktop", about = "Contrôleur et hôte Cyclar")]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
    #[arg(long, default_value = "0.0.0.0:7420")]
    listen: SocketAddr,
    #[arg(long)]
    advertise: Option<String>,
    #[arg(long)]
    state: Option<PathBuf>,
    #[arg(long, default_value = "Poste Cyclar")]
    name: String,
    /// Empêche tout contrôleur distant d'injecter des entrées sur ce poste.
    #[arg(long)]
    view_only_host: bool,
    /// Accepter des offres de fichiers entrantes après approbation locale.
    #[arg(long)]
    allow_files: bool,
    /// Ne publie aucun port direct pour les sessions entrantes.
    #[arg(long)]
    relay_only: bool,
    /// Ouvre directement une session vers l'ID demandé.
    #[arg(long)]
    connect: Option<u64>,
    /// Publier une offre de fichier après connexion, sans lecture anticipée.
    #[arg(long, requires = "connect")]
    send_file: Option<PathBuf>,
    /// Demande uniquement la capacité de lecture pour la session sortante.
    #[arg(long)]
    view_only: bool,
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    use std::io::{self, Write};

    use cyclar_desktop::api::CentralApi;
    use cyclar_desktop::host::{self, HostOptions};

    let args = Args::parse();
    let api = CentralApi::new(&args.server)?;
    let mut host = host::start(HostOptions {
        server_url: args.server,
        listen: args.listen,
        advertise: args.advertise,
        state_path: args
            .state
            .unwrap_or_else(cyclar_desktop::identity::default_state_path),
        name: args.name,
        view_only: args.view_only_host,
        allow_files: args.allow_files,
        relay_only: args.relay_only,
    })?;
    if let Some(alias) = args.connect {
        connect_prompt(&api, alias, args.view_only, args.send_file);
    }
    println!("Commandes : connect <ID>, send <ID> <fichier>, secret, rotate, set-password, clear-password, status, sessions, kick <session>, files, approve <transfert> <dossier>, quit");
    let stdin = io::stdin();
    loop {
        print!("cyclar> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        let mut words = line.split_whitespace();
        match words.next() {
            Some("connect") => match words.next().and_then(|value| value.parse::<u64>().ok()) {
                Some(alias) => connect_prompt(&api, alias, args.view_only, None),
                None => println!("Indiquez un ID numérique : connect 123456"),
            },
            Some("send") => {
                let rest = line.trim().strip_prefix("send").unwrap_or("").trim_start();
                let parsed = rest.find(char::is_whitespace).and_then(|index| {
                    let alias = rest[..index].parse::<u64>().ok()?;
                    let path = rest[index..].trim_start();
                    if path.is_empty() { None } else { Some((alias, PathBuf::from(path))) }
                });
                match parsed {
                    Some((alias, path)) => connect_prompt(&api, alias, args.view_only, Some(path)),
                    None => println!("Usage : send <ID distant> <chemin du fichier>"),
                }
            }
            Some("status") => println!(
                "ID local {} · {} participant(s).",
                host.identity.alias,
                host.participants()
            ),
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
                    (Ok(first), Ok(second)) if first == second => match host.set_permanent_password(Some(&first)) {
                        Ok(()) => println!("Mot de passe permanent confirmé par le serveur."),
                        Err(error) => eprintln!("Mot de passe refusé : {error}"),
                    },
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
                let rest = line.trim().strip_prefix("approve").unwrap_or("").trim_start();
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
            Some("quit" | "q" | "exit") => break,
            Some("help") => println!(
                "Commandes : connect <ID>, send <ID> <fichier>, secret, rotate, set-password, clear-password, status, sessions, kick <session>, files, approve <transfert> <dossier>, quit"
            ),
            Some(_) | None => println!("Commande inconnue. Tapez help."),
        }
    }
    host.stop();
    Ok(())
}

#[cfg(target_os = "linux")]
fn connect_prompt(
    api: &cyclar_desktop::api::CentralApi,
    alias: u64,
    view_only: bool,
    send_file: Option<PathBuf>,
) {
    match rpassword::prompt_password("Secret de la machine distante : ") {
        Ok(password) => {
            if let Err(error) =
                cyclar_desktop::controller::connect(api, alias, password, view_only, send_file)
            {
                eprintln!("Connexion impossible : {error}");
            }
        }
        Err(error) => eprintln!("Saisie du secret impossible : {error}"),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    let _ = Args::parse();
    anyhow::bail!("Aucun backend de capture/rendu natif qualifié pour cet OS. Cette version ne fournit que Linux/X11.")
}
