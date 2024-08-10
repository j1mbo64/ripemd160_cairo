// All test hashes were calculated using the RIPEMD-160 function in the linux Openssl binary.
#[cfg(test)]
mod tests {
    use ripemd160::ripemd160::{RIPEMD160Context, ripemd160_hash, ripemd160_context_as_u256};

    #[test]
    fn ripemd160_test_empty() {
        let message: ByteArray = "";
        let mut ctx: RIPEMD160Context = ripemd160_hash(@message);
        let hash = ripemd160_context_as_u256(@ctx);
        let expected_hash: u256 = 0x9c1185a5c5e9fc54612808977ee8f548b2258d31;
        assert_eq!(hash, expected_hash, "Bad RIPEMD-160 Hash");
    }

    #[test]
    fn ripemd160_test_1() {
        let message: ByteArray = "toto";
        let mut ctx: RIPEMD160Context = ripemd160_hash(@message);
        let hash = ripemd160_context_as_u256(@ctx);
        let expected_hash: u256 = 0x5dd22b8b0610a48b81bb400732a0fb299d48c21f;
        assert_eq!(hash, expected_hash, "Bad RIPEMD-160 Hash");
    }

    #[test]
    fn ripemd160_test_2() {
        let message: ByteArray = "Hello World !\n";
        let mut ctx: RIPEMD160Context = ripemd160_hash(@message);
        let hash = ripemd160_context_as_u256(@ctx);
        let expected_hash: u256 = 0x7c378d285d7e7354db8bf08bfc5240764b758304;
        assert_eq!(hash, expected_hash, "Bad RIPEMD-160 Hash");
    }

    #[test]
    fn ripemd160_test_3() {
        let message: ByteArray = "1234567890123456789012345678901234567890123456789012345678901234";
        let mut ctx: RIPEMD160Context = ripemd160_hash(@message);
        let hash = ripemd160_context_as_u256(@ctx);
        let expected_hash: u256 = 0xfa8c1a78eb763bb97d5ea14ce9303d1ce2f33454;
        assert_eq!(hash, expected_hash, "Bad RIPEMD-160 Hash");
    }

    #[test]
    fn ripemd160_test_4() {
        let message: ByteArray =
            "utvyHvg5DaRCS09uTHeRb5LG9N2I2AJ1mC7g9Lt6U1iX050ZY4381GBpv76wIzHrae4k85HOX8bQkih15dnhI0qZ64";
        let mut ctx: RIPEMD160Context = ripemd160_hash(@message);
        let hash = ripemd160_context_as_u256(@ctx);
        let expected_hash: u256 = 0xbcc851cf10aec5075cd2b313b148b6315e009158;
        assert_eq!(hash, expected_hash, "Bad RIPEMD-160 Hash");
    }

    #[test]
    fn ripemd160_test_5() {
        let message: ByteArray =
            "6884QYmtkLS4IwK5F0xDYZB0wALHxWL8ycaIcQPdJtITlqdm8Lod6737DDx53wBh10u0vLs1uvMO97njQd6w4OIBvykD8A80R7U1Lcy2Dvvpc7Iev1hom4isr0yth43aL8V8V4i2JB9DuOmHpmG4W5O7CJzBAUJmn2FmlB7Wvdl454FH98t0CaAn5DUQ8w8UVuKkN2FX21c2JN4H0vz77d26I3L01kndyEP1hrXU7TkQpG8NY60765N38jf70VokvUz6q3eYT2FlU8ez2WvoL1P8059n3885wUfxkS2J67skXnS5OKO7LZSS43i1uRoB6T0pAoRs2C6tO30A4lst7iCrED9k0Q097YhlBMis7U33xda5kGzMV30HM2XZ7dOpR1Ze02hGygEAph4Kl34SD1gFCGUO4vxShy34Ktdz08vY8w5BPe46qE0kY5Wwdipv36uuGn75kq66TSR63s51c6n1135UNNlbH5v70n9h9S6D4D7E1h50";
        let mut ctx: RIPEMD160Context = ripemd160_hash(@message);
        let hash = ripemd160_context_as_u256(@ctx);
        let expected_hash: u256 = 0x9071da69a09d137eb75d11d643b8b8d7225d50f1;
        assert_eq!(hash, expected_hash, "Bad RIPEMD-160 Hash");
    }
}
