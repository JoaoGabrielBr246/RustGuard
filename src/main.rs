extern crate select;
extern crate reqwest;

use select::document::Document;
use select::predicate::{Name, Attr, Comment};
use std::io;
use reqwest::header::HeaderMap; 
use std::net::{TcpStream, UdpSocket, SocketAddr};
use std::str::FromStr;
use std::time::Duration;



fn main() {
    println!("Código desenvolvido por João Gabriel.");
    println!("GitHub: https://github.com/JoaoGabrielBr246");
    println!("Este código é apenas para fins de estudo de programação e segurança da informação.");
    
    println!(r"
    __________                __     ________                       .___
    \______   \__ __  _______/  |_  /  _____/ __ _______ _______  __| _/
     |       _/  |  \/  ___/\   __\/   \  ___|  |  \__  \\_  __ \/ __ | 
     |    |   \  |  /\___ \  |  |  \    \_\  \  |  // __ \|  | \/ /_/ | 
     |____|_  /____//____  > |__|   \______  /____/(____  /__|  \____ | 
            \/           \/                \/           \/           \/ 
    
            ");

    println!("Digite a URL do site para análise:");
    let mut url = String::new();
    io::stdin().read_line(&mut url).expect("Falha ao ler a entrada");

    let url = url.trim();

    let response = reqwest::blocking::get(url);
    let response = match response {
        Ok(res) => res,
        Err(err) => panic!("Erro ao realizar a requisição HTTP: {}", err),
    };

    let headers = response.headers().clone();

    let html = match response.text() {
        Ok(body) => body,
        Err(err) => panic!("Erro ao ler o corpo da resposta HTTP: {}", err),
    };

    let document = Document::from(html.as_str());
    println!("Escolha o tipo de análise:");
    println!("1. XSS (Cross-Site Scripting)");
    println!("2. SQL Injection");
    println!("3. Análise de Links");
    println!("4. Análise de Cabeçalhos HTTP");
    println!("5. Verificar Segurança de Transporte");
    println!("6. Verificar Portas TCP e UDP Abertas");

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).expect("Falha ao ler a entrada");
    let choice: u32 = choice.trim().parse().expect("Entrada inválida");

    match choice {
        1 => analyze_xss(&document),
        2 => analyze_sql_injection(&document),
        3 => analyze_links(&document),
        4 => analyze_headers(&headers),
        5 => check_transport_security(url),
        6 => check_open_ports(url),
        _ => println!("Escolha inválida!"),
    }
}

fn analyze_xss(document: &Document) {
    println!("Analisando XSS (Cross-Site Scripting)...");
    let mut xss_found = false;

    for node in document.find(Name("script")) {
        println!("Possível XSS encontrado em script: {}", node.text());
        xss_found = true;
    }

    for node in document.find(Name("a")) {
        if let Some(href) = node.attr("href") {
            if href.starts_with("javascript:") {
                println!("Possível XSS encontrado em link: {}", href);
                xss_found = true;
            }
        }
    }

    for node in document.find(Attr("on*", ())) {
        println!("Possível XSS encontrado em atributo de evento: {:?}", node);
        xss_found = true;
    }

    for node in document.find(Comment) {
        println!("Comentário HTML encontrado: {}", node.text());
    }

    if !xss_found {
        println!("Nenhuma vulnerabilidade de XSS encontrada.");
    }
}

fn analyze_sql_injection(document: &Document) {
    println!("Analisando possíveis vulnerabilidades de SQL Injection...");
    let mut sql_injection_found = false;

    for node in document.find(Attr("type", "text")) {
        let input_name = node.attr("name").unwrap_or_default();
        println!("Verificando campo de entrada: {}", input_name);

        if let Some(parent) = node.parent() {
            if parent.find(Name("script")).count() > 0 {
                println!("Possível SQL Injection encontrado: campo pode ser usado em contexto de script.");
                sql_injection_found = true;
            }
        }
    }

    if !sql_injection_found {
        println!("Nenhuma vulnerabilidade de SQL Injection encontrada.");
    }
}

fn analyze_links(document: &Document) {
    println!("Analisando Links...");
    let mut links_found = false;

    for node in document.find(Name("a")) {
        if let Some(href) = node.attr("href") {
            println!("Link encontrado: {}", href);
            links_found = true;
        }
    }

    if !links_found {
        println!("Nenhum link encontrado na página.");
    }
}

fn analyze_headers(headers: &HeaderMap) {
    println!("Analisando cabeçalhos HTTP...");

    for (name, value) in headers.iter() {
        println!("{}: {}", name.as_str(), value.to_str().unwrap_or_default());
    }

    println!("Verificando políticas de segurança HTTP...");

    if let Some(csp_header) = headers.get("Content-Security-Policy") {
        println!("A política de segurança de conteúdo (CSP) está presente: {:?}", csp_header);
    } else {
        println!("Aviso: A política de segurança de conteúdo (CSP) não está presente.");
    }

    if let Some(cors_header) = headers.get("Access-Control-Allow-Origin") {
        println!("O site permite solicitações cross-origin (CORS): {:?}", cors_header);
    } else {
        println!("Aviso: O site não permite solicitações cross-origin (CORS).");
    }
}

fn check_transport_security(url: &str) {
    if url.starts_with("https") {
        println!("O site usa HTTPS, o que é bom para a segurança do transporte.");
    } else {
        println!("Aviso: O site não usa HTTPS. Isso pode comprometer a segurança do transporte.");
    }
}

fn check_open_ports(host: &str) {
    println!("Verificando portas TCP e UDP abertas para {}", host);

    let common_ports: [u16; 5] = [21, 22, 80, 443, 8080]; 

    println!("Portas TCP abertas:");
    for &port in common_ports.iter() {
        if is_port_open_tcp(host, port) {
            println!("{}: Aberta", port);
        }
    }

    println!("Portas UDP abertas:");
    for &port in common_ports.iter() {
        if is_port_open_udp(host, port) {
            println!("{}: Aberta", port);
        }
    }
}

fn is_port_open_tcp(host: &str, port: u16) -> bool {
    let socket_addr = format!("{}:{}", host, port);
    let addr = match SocketAddr::from_str(&socket_addr) {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    if let Ok(_) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        return true;
    }
    false
}

fn is_port_open_udp(host: &str, port: u16) -> bool {
    let socket_addr = format!("{}:{}", host, port);
    let addr = match SocketAddr::from_str(&socket_addr) {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        if let Ok(_) = socket.connect(&addr) {
            return true;
        }
    }
    false
}
