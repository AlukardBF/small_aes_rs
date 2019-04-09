use std::io::{BufReader, BufWriter, Read, Write};
//Block length in bytes AES is 128b block only
const AES_BLOCKLEN: usize = 16;
// Key length in bytes
const AES_KEYLEN: usize = 16;
const AES_KEY_EXP_SIZE: usize = 176;
// The number of columns comprising a state in AES. This is a constant in AES. Value = 4
const NB: usize = 4;
// The number of 32 bit words in a key.
const NK: usize = 4;
// The number of rounds in AES Cipher.
const NR: usize = 10;
const SBOX: [u8; 256] = [
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];
const RSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];
pub type AESKey = [u8; AES_KEYLEN];
pub type Block = [u8; AES_BLOCKLEN];
type RoundKey = [u8; AES_KEY_EXP_SIZE];
// State - array holding the intermediate results during decryption.
type State = [[u8; 4]; 4];
// The round constant word array, RCON[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
const RCON: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

pub struct AesCtx {
    round_key: RoundKey,
    iv: Block,
}
/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
impl AesCtx {
    pub fn new(key: AESKey) -> AesCtx {
        let mut round_key: RoundKey = [0u8; AES_KEY_EXP_SIZE];
        key_expansion(&mut round_key, key);
        let iv: Block = rand::random();
        AesCtx { round_key, iv }
    }
    pub fn with_iv(key: AESKey, iv: Block) -> AesCtx {
        let mut round_key: RoundKey = [0u8; AES_KEY_EXP_SIZE];
        key_expansion(&mut round_key, key);
        let iv: Block = iv;
        AesCtx { round_key, iv }
    }
    pub fn aes_ctx_set_iv(&mut self, iv: Block) {
        self.iv = iv;
    }
    pub fn aes_cbc_encrypt_buffer<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> std::io::Result<()> {
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);
        
        let mut block: Block = Default::default();
        while reader.read(&mut block)? != 0 {
            let block_len = block.len();
            // Pad block with zeros
            if block_len != AES_BLOCKLEN {
                for i in block_len..AES_BLOCKLEN {
                    block[i] = 0u8;
                }
            }
            // Encrypt
            let encrypted_block = self.aes_cbc_encrypt_block(block);
            writer.write_all(&encrypted_block)?;
        }
        Ok(())
    }
    pub fn aes_cbc_decrypt_buffer<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> std::io::Result<()> {
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        let mut block: Block = Default::default();
        let mut buffer: Vec<u8> = Vec::new();
        while reader.read(&mut block)? != 0 {
            let to_write = buffer.drain(..).collect::<Vec<_>>();
            writer.write_all(&to_write)?;
            let decrypted_block = self.aes_cbc_decrypt_block(block);
            buffer.extend_from_slice(&decrypted_block);
        }
        // Removes zeros
        while buffer.last().unwrap() == &0u8 {
            buffer.pop();
        }
        let to_write = buffer.drain(..).collect::<Vec<_>>();
        writer.write_all(&to_write)?;
        Ok(())
    }
    #[deprecated(since = "0.1.1", note = "Use better alternative aes_cbc_encrypt_buffer")]
    pub fn aes_cbc_encrypt_slice(&mut self, buffer: &[u8]) -> Vec<u8> {
        let mut encrypted: Vec<u8> = Vec::with_capacity(buffer.len());
        let iterations = buffer.len() / AES_BLOCKLEN;
        for i in 0..iterations {
            let start_index = i * AES_BLOCKLEN;
            let end_index = start_index + AES_BLOCKLEN;
            let block = *as_array(&buffer[start_index..end_index]);
            let encrypted_block = self.aes_cbc_encrypt_block(block);
            encrypted.extend_from_slice(&encrypted_block);
        }
        // Block padding
        let mut block_to_fill = Vec::with_capacity(AES_BLOCKLEN);
        block_to_fill.extend_from_slice(&buffer[(iterations * AES_BLOCKLEN)..]);
        if block_to_fill.len() == 0 {
            return encrypted;
        }
        while block_to_fill.len() != AES_BLOCKLEN {
            block_to_fill.push(0u8);
        }
        let block = *as_array(&block_to_fill[..]);
        let encrypted_block = self.aes_cbc_encrypt_block(block);
        encrypted.extend_from_slice(&encrypted_block);
        encrypted
    }
    #[deprecated(since = "0.1.1", note = "Use better alternative aes_cbc_decrypt_buffer")]
    pub fn aes_cbc_decrypt_slice(&mut self, buffer: &[u8]) -> Vec<u8> {
        let mut decrypted: Vec<u8> = Vec::with_capacity(buffer.len());
        for i in 0..(buffer.len() / AES_BLOCKLEN) {
            let start_index = i * AES_BLOCKLEN;
            let end_index = start_index + AES_BLOCKLEN;
            let block = *as_array(&buffer[start_index..end_index]);
            let decrypted_block = self.aes_cbc_decrypt_block(block);
            decrypted.extend_from_slice(&decrypted_block);
        }
        // Remove last zeros
        while decrypted.last().unwrap() == &0u8 {
            decrypted.pop();
        }
        decrypted
    }
    pub fn aes_cbc_encrypt_block(&mut self, block: Block) -> Block {
        let mut block = block;
        xor_with_iv(&mut block, self.iv);
        let mut state = *from_block_to_state(&block);
        cipher(&mut state, self.round_key);
        let encrypted_block = *from_state_to_block(&state);
        self.iv = encrypted_block;
        encrypted_block
    }
    pub fn aes_cbc_decrypt_block(&mut self, block: Block) -> Block {
        let mut state = *from_block_to_state(&block);
        inv_cipher(&mut state, self.round_key);
        let mut decrypted_block = *from_state_to_block(&state);
        xor_with_iv(&mut decrypted_block, self.iv);
        self.iv = block;
        decrypted_block
    }
}
/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
fn from_block_to_state(block: &Block) -> &State {
    unsafe { &*(block as *const Block as *const State) }
}
fn from_state_to_block(state: &State) -> &Block {
    unsafe { &*(state as *const State as *const Block) }
}
fn as_array(slice: &[u8]) -> &Block {
    if slice.len() != AES_BLOCKLEN {
        panic!("slice must be AES_BLOCKLEN length");
    }
    unsafe {
        &*(slice.as_ptr() as *const [_; AES_BLOCKLEN])
    }
}

fn get_sbox_value(num: u8) -> u8 {
    SBOX[num as usize]
}
fn get_sbox_invert(num: u8) -> u8 {
    RSBOX[num as usize]
}
// This function produces NB(NR+1) round keys. The round keys are used in each round to decrypt the states.
fn key_expansion(round_key: &mut RoundKey, key: AESKey) {
    let mut temp = [0u8; 4];

    // The first round key is the key itself.
    for i in 0..NK as usize {
        round_key[(i * 4)] = key[(i * 4)];
        round_key[(i * 4) + 1] = key[(i * 4) + 1];
        round_key[(i * 4) + 2] = key[(i * 4) + 2];
        round_key[(i * 4) + 3] = key[(i * 4) + 3];
    }
    // All other round keys are found from the previous round keys.
    // let end = (NB * (NR + 1)) as usize;
    for i in NK..(NB * (NR + 1)) as usize {
        {
            let k = (i - 1) * 4;
            temp[0] = round_key[k];
            temp[1] = round_key[k + 1];
            temp[2] = round_key[k + 2];
            temp[3] = round_key[k + 3];
        }
        if i % NK == 0 {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            {
                let u8tmp = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = u8tmp;
            }
            // This is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.
            {
                temp[0] = get_sbox_value(temp[0]);
                temp[1] = get_sbox_value(temp[1]);
                temp[2] = get_sbox_value(temp[2]);
                temp[3] = get_sbox_value(temp[3]);
            }
            temp[0] ^= RCON[i / NK]
        }
        let j = i * 4;
        let k = (i - NK) * 4;
        round_key[j] = round_key[k] ^ temp[0];
        round_key[j + 1] = round_key[k + 1] ^ temp[1];
        round_key[j + 2] = round_key[k + 2] ^ temp[2];
        round_key[j + 3] = round_key[k + 3] ^ temp[3];
    }
}
// This function adds the round key to state.
// The round key is added to the state by an XOR function.
fn add_round_key(round: u8, state: &mut State, round_key: RoundKey) {
    for i in 0..4 {
        for j in 0..4 {
            (*state)[i][j] ^= round_key[(usize::from(round) * NB * 4) + (i * NB) + j];
        }
    }
}
// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
fn sub_bytes(state: &mut State) {
    for i in 0..4 {
        for j in 0..4 {
            (*state)[j][i] = get_sbox_value((*state)[j][i]);
        }
    }
}
// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
fn shift_rows(state: &mut State) {
    // Rotate first row 1 columns to left
    let mut temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;
    // Rotate second row 2 columns to left
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;
    // Rotate third row 3 columns to left
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}
fn xtime(x: u8) -> u8 {
    ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
}
// MixColumns function mixes the columns of the state matrix
fn mix_columns(state: &mut State) {
    let mut tm: u8;
    for i in 0..4 {
        let t = (*state)[i][0];
        let tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        tm = (*state)[i][0] ^ (*state)[i][1];
        tm = xtime(tm);
        (*state)[i][0] ^= tm ^ tmp;
        tm = (*state)[i][1] ^ (*state)[i][2];
        tm = xtime(tm);
        (*state)[i][1] ^= tm ^ tmp;
        tm = (*state)[i][2] ^ (*state)[i][3];
        tm = xtime(tm);
        (*state)[i][2] ^= tm ^ tmp;
        tm = (*state)[i][3] ^ t;
        tm = xtime(tm);
        (*state)[i][3] ^= tm ^ tmp;
    }
}
// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
fn multiply(x: u8, y: u8) -> u8 {
    (((y & 1) * x)
        ^ ((y >> 1 & 1) * xtime(x))
        ^ ((y >> 2 & 1) * xtime(xtime(x)))
        ^ ((y >> 3 & 1) * xtime(xtime(xtime(x))))
        ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))
}
/* IF CBC */
// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
fn inv_mix_columns(state: &mut State) {
    for i in 0..4 {
        let a = (*state)[i][0];
        let b = (*state)[i][1];
        let c = (*state)[i][2];
        let d = (*state)[i][3];

        (*state)[i][0] =
            multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        (*state)[i][1] =
            multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        (*state)[i][2] =
            multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        (*state)[i][3] =
            multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}
// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
fn inv_sub_bytes(state: &mut State) {
    for i in 0..4 {
        for j in 0..4 {
            (*state)[j][i] = get_sbox_invert((*state)[j][i]);
        }
    }
}
fn inv_shift_rows(state: &mut State) {
    // Rotate first row 1 columns to right
    let mut temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}
// Cipher is the main function that encrypts the PlainText.
fn cipher(state: &mut State, round_key: RoundKey) {
    // Add the First round key to the state before starting the rounds.
    add_round_key(0, state, round_key);

    // There will be NR rounds.
    // The first NR-1 rounds are identical.
    // These NR-1 rounds are executed in the loop below.
    for round in 1..NR as u8 {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(round, state, round_key);
    }
    // The last round is given below.
    // The MixColumns function is not here in the last round.
    sub_bytes(state);
    shift_rows(state);
    add_round_key(NR as u8, state, round_key);
}
fn inv_cipher(state: &mut State, round_key: RoundKey) {
    // Add the First round key to the state before starting the rounds.
    add_round_key(NR as u8, state, round_key);

    // There will be NR rounds.
    // The first NR-1 rounds are identical.
    // These NR-1 rounds are executed in the loop below.
    for round in (1..NR as u8).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(round, state, round_key);
        inv_mix_columns(state);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(0, state, round_key);
}
fn xor_with_iv(buf: &mut Block, iv: Block) {
    for i in 0..AES_BLOCKLEN {
        buf[i] ^= iv[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_cbc_encrypt() {
        let key: AESKey = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: Block = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let source_text = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ]
        .to_vec();
        let result_text = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
            0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16,
            0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ]
        .to_vec();
        let mut cipher = AesCtx::new(key);
        cipher.aes_ctx_set_iv(iv);
        let encrypted_text = cipher.aes_cbc_encrypt_slice(&source_text);
        assert_eq!(result_text, encrypted_text);
    }

    #[test]
    fn test_aes_128_cbc_decrypt() {
        let key: AESKey = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: Block = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let result_text = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
        ]
        .to_vec();
        let source_text = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
            0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16,
            0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ]
        .to_vec();
        let mut cipher = AesCtx::new(key);
        cipher.aes_ctx_set_iv(iv);
        let decrypted_text = cipher.aes_cbc_decrypt_slice(&source_text);
        assert_eq!(result_text, decrypted_text);
    }
}
