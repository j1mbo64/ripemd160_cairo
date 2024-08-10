use ripemd160::utils::{
    POW_2_32, POW_2_8, get_pow_2, bytes_to_u32, leftrotate, u32_mod_add, byte_swap_u32
};

const BLOCK_SIZE: u32 = 64;
const BLOCK_SIZE_WO_LEN: u32 = 56;

#[derive(Drop, Clone, Copy)]
pub struct RIPEMD160Context {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

pub impl RIPEMD160ContextIntoU256 of Into<RIPEMD160Context, u256> {
    fn into(self: RIPEMD160Context) -> u256 {
        ripemd160_context_as_u256(@self)
    }
}

pub impl RIPEMD160ContextIntoBytes of Into<RIPEMD160Context, ByteArray> {
    fn into(self: RIPEMD160Context) -> ByteArray {
        ripemd160_context_as_bytes(@self)
    }
}

pub impl RIPEMD160ContextIntoArray of Into<RIPEMD160Context, Array<u32>> {
    fn into(self: RIPEMD160Context) -> Array<u32> {
        ripemd160_context_as_array(@self)
    }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (~x & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    (x | ~y) ^ z
}

fn i(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & ~z)
}

fn j(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | ~z)
}

fn l1(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(f(b, c, d), x));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn l2(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(g(b, c, d), u32_mod_add(x, 0x5a827999)));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn l3(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(h(b, c, d), u32_mod_add(x, 0x6ed9eba1)));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn l4(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(i(b, c, d), u32_mod_add(x, 0x8f1bbcdc)));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn l5(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(j(b, c, d), u32_mod_add(x, 0xa953fd4e)));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn r1(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(j(b, c, d), u32_mod_add(x, 0x50a28be6)));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn r2(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(i(b, c, d), u32_mod_add(x, 0x5c4dd124)));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn r3(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(h(b, c, d), u32_mod_add(x, 0x6d703ef3)));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn r4(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(g(b, c, d), u32_mod_add(x, 0x7a6d76e9)));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

fn r5(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add(a, u32_mod_add(f(b, c, d), x));
    a = u32_mod_add(leftrotate(a, s), e);
    c = leftrotate(c, 10);
}

// RIPEMD-160 compression function
fn ripemd160_process_block(ref ctx: RIPEMD160Context, data: @Array<u32>) {
    let mut lh0 = ctx.h0;
    let mut lh1 = ctx.h1;
    let mut lh2 = ctx.h2;
    let mut lh3 = ctx.h3;
    let mut lh4 = ctx.h4;
    let mut rh0 = ctx.h0;
    let mut rh1 = ctx.h1;
    let mut rh2 = ctx.h2;
    let mut rh3 = ctx.h3;
    let mut rh4 = ctx.h4;

    // Left Round 1
    l1(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(0), 11);
    l1(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(1), 14);
    l1(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(2), 15);
    l1(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(3), 12);
    l1(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(4), 5);
    l1(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(5), 8);
    l1(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(6), 7);
    l1(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(7), 9);
    l1(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(8), 11);
    l1(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(9), 13);
    l1(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(10), 14);
    l1(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(11), 15);
    l1(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(12), 6);
    l1(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(13), 7);
    l1(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(14), 9);
    l1(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(15), 8);

    // Left Round 2
    l2(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(7), 7);
    l2(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(4), 6);
    l2(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(13), 8);
    l2(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(1), 13);
    l2(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(10), 11);
    l2(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(6), 9);
    l2(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(15), 7);
    l2(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(3), 15);
    l2(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(12), 7);
    l2(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(0), 12);
    l2(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(9), 15);
    l2(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(5), 9);
    l2(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(2), 11);
    l2(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(14), 7);
    l2(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(11), 13);
    l2(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(8), 12);

    // Left Round 3
    l3(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(3), 11);
    l3(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(10), 13);
    l3(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(14), 6);
    l3(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(4), 7);
    l3(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(9), 14);
    l3(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(15), 9);
    l3(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(8), 13);
    l3(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(1), 15);
    l3(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(2), 14);
    l3(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(7), 8);
    l3(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(0), 13);
    l3(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(6), 6);
    l3(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(13), 5);
    l3(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(11), 12);
    l3(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(5), 7);
    l3(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(12), 5);

    // Left Round 4
    l4(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(1), 11);
    l4(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(9), 12);
    l4(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(11), 14);
    l4(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(10), 15);
    l4(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(0), 14);
    l4(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(8), 15);
    l4(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(12), 9);
    l4(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(4), 8);
    l4(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(13), 9);
    l4(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(3), 14);
    l4(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(7), 5);
    l4(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(15), 6);
    l4(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(14), 8);
    l4(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(5), 6);
    l4(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(6), 5);
    l4(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(2), 12);

    // Left Round 5
    l5(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(4), 9);
    l5(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(0), 15);
    l5(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(5), 5);
    l5(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(9), 11);
    l5(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(7), 6);
    l5(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(12), 8);
    l5(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(2), 13);
    l5(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(10), 12);
    l5(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(14), 5);
    l5(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(1), 12);
    l5(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(3), 13);
    l5(ref lh0, lh1, ref lh2, lh3, lh4, *data.at(8), 14);
    l5(ref lh4, lh0, ref lh1, lh2, lh3, *data.at(11), 11);
    l5(ref lh3, lh4, ref lh0, lh1, lh2, *data.at(6), 8);
    l5(ref lh2, lh3, ref lh4, lh0, lh1, *data.at(15), 5);
    l5(ref lh1, lh2, ref lh3, lh4, lh0, *data.at(13), 6);

    // Right Round 1
    r1(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(5), 8);
    r1(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(14), 9);
    r1(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(7), 9);
    r1(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(0), 11);
    r1(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(9), 13);
    r1(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(2), 15);
    r1(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(11), 15);
    r1(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(4), 5);
    r1(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(13), 7);
    r1(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(6), 7);
    r1(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(15), 8);
    r1(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(8), 11);
    r1(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(1), 14);
    r1(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(10), 14);
    r1(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(3), 12);
    r1(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(12), 6);

    // Right Round 2
    r2(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(6), 9);
    r2(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(11), 13);
    r2(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(3), 15);
    r2(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(7), 7);
    r2(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(0), 12);
    r2(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(13), 8);
    r2(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(5), 9);
    r2(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(10), 11);
    r2(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(14), 7);
    r2(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(15), 7);
    r2(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(8), 12);
    r2(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(12), 7);
    r2(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(4), 6);
    r2(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(9), 15);
    r2(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(1), 13);
    r2(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(2), 11);

    // Right Round 3
    r3(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(15), 9);
    r3(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(5), 7);
    r3(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(1), 15);
    r3(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(3), 11);
    r3(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(7), 8);
    r3(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(14), 6);
    r3(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(6), 6);
    r3(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(9), 14);
    r3(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(11), 12);
    r3(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(8), 13);
    r3(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(12), 5);
    r3(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(2), 14);
    r3(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(10), 13);
    r3(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(0), 13);
    r3(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(4), 7);
    r3(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(13), 5);

    // Right Round 4
    r4(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(8), 15);
    r4(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(6), 5);
    r4(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(4), 8);
    r4(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(1), 11);
    r4(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(3), 14);
    r4(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(11), 14);
    r4(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(15), 6);
    r4(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(0), 14);
    r4(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(5), 6);
    r4(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(12), 9);
    r4(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(2), 12);
    r4(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(13), 9);
    r4(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(9), 12);
    r4(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(7), 5);
    r4(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(10), 15);
    r4(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(14), 8);

    // Right Round 5
    r5(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(12), 8);
    r5(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(15), 5);
    r5(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(10), 12);
    r5(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(4), 9);
    r5(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(1), 12);
    r5(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(5), 5);
    r5(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(8), 14);
    r5(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(7), 6);
    r5(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(6), 8);
    r5(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(2), 13);
    r5(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(13), 6);
    r5(ref rh0, rh1, ref rh2, rh3, rh4, *data.at(14), 5);
    r5(ref rh4, rh0, ref rh1, rh2, rh3, *data.at(0), 15);
    r5(ref rh3, rh4, ref rh0, rh1, rh2, *data.at(3), 13);
    r5(ref rh2, rh3, ref rh4, rh0, rh1, *data.at(9), 11);
    r5(ref rh1, rh2, ref rh3, rh4, rh0, *data.at(11), 11);

    // Combine results
    rh3 = u32_mod_add(ctx.h1, u32_mod_add(lh2, rh3));
    ctx.h1 = u32_mod_add(ctx.h2, u32_mod_add(lh3, rh4));
    ctx.h2 = u32_mod_add(ctx.h3, u32_mod_add(lh4, rh0));
    ctx.h3 = u32_mod_add(ctx.h4, u32_mod_add(lh0, rh1));
    ctx.h4 = u32_mod_add(ctx.h0, u32_mod_add(lh1, rh2));
    ctx.h0 = rh3;
}

// Add RIPEMD-160 padding to the input.
fn ripemd160_padding(ref data: ByteArray) {
    // Get message len in bits
    let mut data_bits_len: u64 = data.len().into() * 8;

    // Append padding bit
    data.append_byte(0x80);

    // Add padding zeroes
    let mut len = data.len();
    while (len % BLOCK_SIZE != BLOCK_SIZE_WO_LEN) {
        data.append_byte(0);
        len += 1;
    };

    // Add message len in little-endian
    while (data_bits_len != 0) {
        let byte: u8 = (data_bits_len % 256).try_into().unwrap();
        data_bits_len = (data_bits_len / 256).try_into().unwrap();
        data.append_byte(byte);
    };

    // Add zeroes to complete block
    len = data.len();
    while (len % BLOCK_SIZE != 0) {
        data.append_byte(0);
        len += 1;
    }
}

// Update the context by processing the whole data.
fn ripemd160_update(ref ctx: RIPEMD160Context, data: ByteArray) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let len = data.len();
    while (i != len) {
        let mut block: Array<u32> = ArrayTrait::new();
        j = 0;
        while (j < BLOCK_SIZE) {
            block.append(bytes_to_u32(@data, i));
            j += 4;
            i += 4;
        };
        ripemd160_process_block(ref ctx, @block);
    };
}

// Init context with RIPEMD-160 constant.
fn ripemd160_init() -> RIPEMD160Context {
    RIPEMD160Context {
        h0: 0x67452301, h1: 0xefcdab89, h2: 0x98badcfe, h3: 0x10325476, h4: 0xc3d2e1f0,
    }
}

// Return hash as bytes.
pub fn ripemd160_context_as_bytes(ctx: @RIPEMD160Context) -> ByteArray {
    let mut result: ByteArray = Default::default();
    let mask: u32 = 0x000000FF;

    let mut value = *ctx.h0;
    while (value >= POW_2_8) {
        result.append_byte((value & mask).try_into().unwrap());
        value = value / POW_2_8;
    };
    result.append_byte((value & mask).try_into().unwrap());

    let mut value = *ctx.h1;
    while (value >= POW_2_8) {
        result.append_byte((value & mask).try_into().unwrap());
        value = value / POW_2_8;
    };
    result.append_byte((value & mask).try_into().unwrap());

    let mut value = *ctx.h2;
    while (value >= POW_2_8) {
        result.append_byte((value & mask).try_into().unwrap());
        value = value / POW_2_8;
    };
    result.append_byte((value & mask).try_into().unwrap());

    let mut value = *ctx.h3;
    while (value >= POW_2_8) {
        result.append_byte((value & mask).try_into().unwrap());
        value = value / POW_2_8;
    };
    result.append_byte((value & mask).try_into().unwrap());

    let mut value = *ctx.h4;
    while (value >= POW_2_8) {
        result.append_byte((value & mask).try_into().unwrap());
        value = value / POW_2_8;
    };
    result.append_byte((value & mask).try_into().unwrap());

    result
}

// Return hash as u32 array.
pub fn ripemd160_context_as_array(ctx: @RIPEMD160Context) -> Array<u32> {
    let mut result: Array<u32> = ArrayTrait::new();
    result.append(*ctx.h0);
    result.append(*ctx.h1);
    result.append(*ctx.h2);
    result.append(*ctx.h3);
    result.append(*ctx.h4);
    result
}

// Return hash as u256.
pub fn ripemd160_context_as_u256(ctx: @RIPEMD160Context) -> u256 {
    let mut result: u256 = 0;
    result += byte_swap_u32(*ctx.h0).into();
    result *= POW_2_32.into();
    result += byte_swap_u32(*ctx.h1).into();
    result *= POW_2_32.into();
    result += byte_swap_u32(*ctx.h2).into();
    result *= POW_2_32.into();
    result += byte_swap_u32(*ctx.h3).into();
    result *= POW_2_32.into();
    result += byte_swap_u32(*ctx.h4).into();
    result
}

// RIPEMD-160 hash function entrypoint.
pub fn ripemd160_hash(data: @ByteArray) -> RIPEMD160Context {
    let mut data = data.clone();
    let mut ctx = ripemd160_init();
    ripemd160_padding(ref data);
    ripemd160_update(ref ctx, data);
    ctx
}
