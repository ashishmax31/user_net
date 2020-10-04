use user_net;
use std::thread;

fn main() {
    user_net::start_stack();
    std::thread::spawn(|| {
        start_client()
    });
    start_server()
}

fn start_server() {
    let server = user_net::udp_socket::bind("10.0.0.2:5055").unwrap();
    let bytes = "Hello from the server".as_bytes();
    loop {
        let mut buf = Vec::with_capacity(1000);
        let (num_bytes, from) = server.recv_from(&mut buf).unwrap();
        println!("<Server> client says: {}", std::str::from_utf8(&buf).unwrap());
        server.send_to(bytes, &from);
    }
}


fn start_client() {
    let client = user_net::udp_socket::bind("10.0.0.2:4055").unwrap();
    client.connect("10.0.0.2:5055").unwrap();
    let bytes = "Hello from the client".as_bytes();
    loop{
        let mut buf = Vec::with_capacity(1000);
        client.send(bytes).unwrap();
        client.recv_from(&mut buf).unwrap();
        println!("<Client> server says: {}", std::str::from_utf8(&buf).unwrap());
    }
}
