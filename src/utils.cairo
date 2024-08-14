pub(crate) const POW_2_32: u64 = 0x100000000;
pub(crate) const POW_2_8: u32 = 256;

pub(crate) fn get_pow_2(n: u32) -> u32 {
    match n {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => 32,
        6 => 64,
        7 => 128,
        8 => 256,
        9 => 512,
        10 => 1024,
        11 => 2048,
        12 => 4096,
        13 => 8192,
        14 => 16384,
        15 => 32768,
        16 => 65536,
        17 => 131072,
        18 => 262144,
        19 => 524288,
        20 => 1048576,
        21 => 2097152,
        22 => 4194304,
        23 => 8388608,
        24 => 16777216,
        25 => 33554432,
        26 => 67108864,
        27 => 134217728,
        28 => 268435456,
        29 => 536870912,
        30 => 1073741824,
        31 => 2147483648,
        _ => 0
    }
}

pub(crate) fn u32_mod_add(a: u32, b: u32) -> u32 {
    let a: u64 = a.into();
    let b: u64 = b.into();
    ((a + b) % POW_2_32).try_into().unwrap()
}

pub(crate) fn u32_mod_add_3(a: u32, b: u32, c: u32) -> u32 {
    let result: u64 = (a.into() + b.into() + c.into()) % POW_2_32;
    result.try_into().unwrap()
}

pub(crate) fn u32_mod_add_4(a: u32, b: u32, c: u32, d: u32) -> u32 {
    let result: u64 = (a.into() + b.into() + c.into() + d.into()) % POW_2_32;
    result.try_into().unwrap()
}

pub(crate) fn u32_mod_mul(a: u32, b: u32) -> u32 {
    let a: u64 = a.into();
    let b: u64 = b.into();
    ((a * b) % POW_2_32).try_into().unwrap()
}

pub(crate) fn u32_leftrotate(x: u32, n: u32) -> u32 {
    let overflow = x / get_pow_2(32 - n);
    let shifted = u32_mod_mul(x, get_pow_2(n));
    shifted | overflow
}

pub(crate) fn u32_byte_swap(mut x: u32) -> u32 {
    let mask: u32 = 0x000000FF;
    let mut result = x & mask;
    result *= POW_2_8;
    x = x / POW_2_8;
    result += x & mask;
    result *= POW_2_8;
    x = x / POW_2_8;
    result += x & mask;
    result *= POW_2_8;
    x = x / POW_2_8;
    result += x & mask;
    result
}

pub(crate) fn bytes_to_u32_swap(bytes: @ByteArray, mut index: usize) -> u32 {
    let mut result: u32 = 0;
    result += bytes.at(index + 3).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index + 2).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index + 1).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index).unwrap().into();
    result
}
