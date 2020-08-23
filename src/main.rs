use user_net::*;

fn main() {
    let socket = match create_link_layer_socket() {
        Ok(fd) => fd,
        Err(err) => panic!(err),
    };
    match bind_to_device(socket, "enp2s0") {
        Ok(_) => println!("Successful binding with interface!"),
        Err(err) => eprintln!("{}", err),
    };
    read_from_socket(socket, 1024);
}
