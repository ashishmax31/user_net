use std::convert::TryInto;

#[inline]
pub fn ntohs(input: &[u8]) -> u16 {
    u16::from_be_bytes(input.try_into().unwrap())
}

#[inline]
pub fn htons(input: &[u8]) -> u16 {
    u16::from_le_bytes(input.try_into().unwrap())
}

#[inline]
pub fn ntohl(input: &[u8]) -> u32 {
    u32::from_be_bytes(input.try_into().unwrap())
}

// Always assumes that that the packet bytes are from the network, so checksums and other multi-byte characters are created
// under the assumption that the byte stream is big-endian.
#[inline]
pub fn compute_ip_checksum(packet: &[u8], checksum_range: std::ops::Range<usize>) -> (u16, u16) {
    let mut packet_clone = packet.to_vec();
    // Add an additional zero byte at the end to make the total length of the byte slice even
    // so that they can be arranged into 16bit characters.
    if packet.len() % 2 != 0 {
        packet_clone.push(0u8);
    }

    let current_checksum = ntohs(&packet_clone[checksum_range.start..checksum_range.end]);

    // Set the checksum bytes to zero before calculating the checksum
    for ind in checksum_range {
        packet_clone[ind] = 0;
    }

    let mut sum = packet_clone.chunks(2).fold(0u32, |mut sum, vals| {
        let curr_val = u16::from_be_bytes(vals.try_into().unwrap());
        sum += curr_val as u32;
        sum
    });
    // Add the overflowed 'carry's if present
    let carry = sum >> 16;
    sum += carry;
    let sum = sum as u16;

    // Finally take the ones compliment of the sum
    (!sum, current_checksum)
}

#[inline]
pub fn get_bits(byte: u8, rng: std::ops::Range<u8>) -> u8 {
    // Find the max decimal for the given range
    let range: u8 = rng.end - rng.start;
    let start = rng.start;
    let and_arg = (u16::pow(2, range.into()) - 1 as u16) as u8;

    // If the range starts from lsb don't shift else left shift `and_arg` `start` times.
    let and_arg = if start > 0 { and_arg << start } else { and_arg };
    // Finally right shift `start` times the and result to get the final result
    (byte & and_arg) >> start
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_get_bits() {
        let x = 240; // 1111 0000

        let res = get_bits(x, 0..4);
        assert_eq!(res, 0);

        let res = get_bits(x, 4..8);
        assert_eq!(res, 15);

        let res = get_bits(x, 4..7);
        assert_eq!(res, 7);

        let res = get_bits(x, 0..8);
        assert_eq!(res, 240);

        let res = get_bits(x, 4..6);
        assert_eq!(res, 3);

        let y = 0b10100110;

        assert_eq!(get_bits(y, 0..3), 6);
        assert_eq!(get_bits(y, 1..3), 3);
    }

    #[test]
    fn test_ntohs() {
        let x: [u8; 2] = [0xab, 0xcc];
        let res = ntohs(&x);
        assert_eq!(res, 0xabcc);
        let r1: u16 = 0xff00;
        let r2: u16 = 0x00ff;
        assert_eq!(res & r1, 0xab00);
        assert_eq!(res & r2, 0x00cc);
    }
    #[test]
    fn test_htons() {
        let x: [u8; 2] = [0xab, 0xcc];
        let res = htons(&x);
        assert_eq!(res, 0xccab);
        let r1: u16 = 0xff00;
        let r2: u16 = 0x00ff;
        assert_eq!(res & r1, 0xcc00);
        assert_eq!(res & r2, 0x00ab);
    }

    #[test]
    fn test_compute_ip_checksum() {
        let mut packet_bytes: [u8; 7] = [1, 2, 1, 2, 1, 2, 1];
        packet_bytes[2] = 0x20;
        packet_bytes[3] = 0x40;
        let (computed_chksum, current_chksum) = compute_ip_checksum(&packet_bytes, 2..4);
        assert_eq!(current_chksum, 0x2040);
        // [1, 2, 0, 0, 1, 2, 1, 0] (Additional zero byte padded)
        // checksum calculation => 0x0102 + 0x0000 + 0x0102 + 0x0100 => 0x304 => 1's compliment(0x304)
        assert_eq!(computed_chksum, !0x304);

        // 16bit overflow carry addition scenario
        let packet_bytes: [u8; 8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let (computed_chksum, _) = compute_ip_checksum(&packet_bytes, 2..4);
        // checksum calculation => 0xffff + 0xffff+ 0xffff => 0x2FFFD => Add the overflowed carry back => 0xfffd + 2 => 0xffff => 1's compliment(0xffff)
        assert_eq!(computed_chksum, 0x0000);
    }
}
