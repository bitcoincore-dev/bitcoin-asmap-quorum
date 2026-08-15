//! Wire-format primitives: instructions, the variable-length integer coder,
//! and the intermediate encoded-node tree.

fn bit_length_u32(v: u32) -> u32 {
    32 - v.leading_zeros()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Instruction {
    Return = 0,
    Jump = 1,
    Match = 2,
    Default = 3,
    End = 4,
}

impl TryFrom<u32> for Instruction {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => Instruction::Return,
            1 => Instruction::Jump,
            2 => Instruction::Match,
            3 => Instruction::Default,
            4 => Instruction::End,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VarLenCoder {
    minval: u32,
    clsbits: &'static [u32],
    maxval: u32,
}

impl VarLenCoder {
    const fn new(minval: u32, clsbits: &'static [u32]) -> Self {
        let mut total = 0u32;
        let mut i = 0;
        while i < clsbits.len() {
            total += 1 << clsbits[i];
            i += 1;
        }
        Self {
            minval,
            clsbits,
            maxval: minval + total - 1,
        }
    }

    pub(crate) fn can_encode(&self, val: u32) -> bool {
        (self.minval..=self.maxval).contains(&val)
    }

    pub(crate) fn encode_size(&self, val: u32) -> usize {
        let mut val = val - self.minval;
        let mut ret = 0usize;
        let mut bits = 0u32;
        for (k, clsbits) in self.clsbits.iter().enumerate() {
            bits = *clsbits;
            if val >> bits != 0 {
                val -= 1 << bits;
                ret += 1;
            } else {
                ret += usize::from(k + 1 < self.clsbits.len());
                break;
            }
        }
        ret + bits as usize
    }

    pub(crate) fn encode(&self, val: u32, ret: &mut Vec<u8>) {
        assert!(self.can_encode(val));
        let mut val = val - self.minval;
        let mut bits = 0u32;
        for (k, clsbits) in self.clsbits.iter().enumerate() {
            bits = *clsbits;
            if val >> bits != 0 {
                val -= 1 << bits;
                ret.push(1);
            } else {
                if k + 1 < self.clsbits.len() {
                    ret.push(0);
                }
                break;
            }
        }
        for b in 0..bits {
            ret.push(((val >> (bits - 1 - b)) & 1) as u8);
        }
    }

    pub(crate) fn decode(&self, stream: &[u8], mut bitpos: usize) -> Option<(u32, usize)> {
        let mut val = self.minval;
        let mut bits = 0u32;
        for (k, clsbits) in self.clsbits.iter().enumerate() {
            bits = *clsbits;
            let mut bit = 0u8;
            if k + 1 < self.clsbits.len() {
                bit = *stream.get(bitpos)?;
                bitpos += 1;
            }
            if bit == 0 {
                break;
            }
            val += 1 << bits;
        }
        for i in 0..bits {
            let bit = *stream.get(bitpos)?;
            bitpos += 1;
            val += (bit as u32) << (bits - 1 - i);
        }
        Some((val, bitpos))
    }
}

#[derive(Debug, Clone)]
pub(crate) enum BinNodeKind {
    Return(u32),
    Jump(Box<BinNode>, Box<BinNode>),
    Match(u32, Box<BinNode>),
    Default(u32, Box<BinNode>),
    End,
}

#[derive(Debug, Clone)]
pub(crate) struct BinNode {
    pub(crate) kind: BinNodeKind,
    pub(crate) size: usize,
}

impl BinNode {
    pub(crate) fn end() -> Self {
        Self {
            kind: BinNodeKind::End,
            size: 0,
        }
    }

    pub(crate) fn leaf(v: u32) -> Self {
        Self {
            kind: BinNodeKind::Return(v),
            size: CODER_INS.encode_size(Instruction::Return as u32) + CODER_ASN.encode_size(v),
        }
    }

    pub(crate) fn branch(left: BinNode, right: BinNode) -> Self {
        if matches!(left.kind, BinNodeKind::End) && matches!(right.kind, BinNodeKind::End) {
            return left;
        }
        if matches!(left.kind, BinNodeKind::End) {
            if let BinNodeKind::Match(v, sub) = right.kind.clone()
                && v <= 0xff
            {
                return Self::match_node(v + (1 << bit_length_u32(v)), *sub);
            }
            return Self::match_node(3, right);
        }
        if matches!(right.kind, BinNodeKind::End) {
            if let BinNodeKind::Match(v, sub) = left.kind.clone()
                && v <= 0xff
            {
                return Self::match_node(v + (1 << (bit_length_u32(v) - 1)), *sub);
            }
            return Self::match_node(2, left);
        }
        let size = CODER_INS.encode_size(Instruction::Jump as u32)
            + CODER_JUMP.encode_size(left.size as u32)
            + left.size
            + right.size;
        Self {
            kind: BinNodeKind::Jump(Box::new(left), Box::new(right)),
            size,
        }
    }

    pub(crate) fn default(v: u32, sub: BinNode) -> Self {
        if matches!(sub.kind, BinNodeKind::End) {
            return Self::leaf(v);
        }
        if matches!(
            sub.kind,
            BinNodeKind::Return(_) | BinNodeKind::Default(_, _)
        ) {
            return sub;
        }
        let size = CODER_INS.encode_size(Instruction::Default as u32)
            + CODER_ASN.encode_size(v)
            + sub.size;
        Self {
            kind: BinNodeKind::Default(v, Box::new(sub)),
            size,
        }
    }

    pub(crate) fn match_node(v: u32, sub: BinNode) -> Self {
        let size = CODER_INS.encode_size(Instruction::Match as u32)
            + CODER_MATCH.encode_size(v)
            + sub.size;
        Self {
            kind: BinNodeKind::Match(v, Box::new(sub)),
            size,
        }
    }

    pub(crate) fn ins_value(&self) -> u32 {
        match self.kind {
            BinNodeKind::Return(_) => Instruction::Return as u32,
            BinNodeKind::Jump(_, _) => Instruction::Jump as u32,
            BinNodeKind::Match(_, _) => Instruction::Match as u32,
            BinNodeKind::Default(_, _) => Instruction::Default as u32,
            BinNodeKind::End => Instruction::End as u32,
        }
    }
}

pub(crate) const CODER_INS: VarLenCoder = VarLenCoder::new(0, &[0, 0, 1]);
pub(crate) const CODER_ASN: VarLenCoder =
    VarLenCoder::new(1, &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24]);
pub(crate) const CODER_MATCH: VarLenCoder = VarLenCoder::new(2, &[1, 2, 3, 4, 5, 6, 7, 8]);
pub(crate) const CODER_JUMP: VarLenCoder = VarLenCoder::new(
    17,
    &[
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
        29, 30,
    ],
);
