use user_net::*;

fn main() {
    let socket = match open_link_layer_socket(){
        Ok(fd) => fd,
        Err(err) => panic!(err)
    };
}
