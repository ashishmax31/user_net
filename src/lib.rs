// use libc::size_t;
use libc::socket;

use nix::errno;

pub fn open_link_layer_socket() -> Result<i32, &'static str> {
    let res;
    unsafe {
        res = socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL);
    }
    match res {
        err_no if err_no < 0 => {
            let err = errno::Errno::last();
            Err(err.desc())
        }
        fd => Ok(fd),
    }
}
