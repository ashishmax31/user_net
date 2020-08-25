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

    let fd = create_tap_device("tap").unwrap();
    let rx = read_from_socket(fd, 1024);
    loop {
        println!("{:?}", rx.recv().unwrap());
    }
}
