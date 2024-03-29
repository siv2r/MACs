// Kmac128Core, Kmac128, CShake128Core,
// 136,  KMAC128, U32
macro_rules! impl_kmac {
    (
        $name:ident, $full_name:ident, $cshakecore:ty,
        $alg_name:expr, $output_size:expr $(,)?
    ) => {
        pub struct $name {
            digest: $cshakecore,
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;

        impl $name {
            // initialize the self.digest with key & function name
            pub fn new(key: &[u8], customization: &[u8]) -> Self {
                let mut core = <$cshakecore>::new_with_function_name(FUNCTION_NAME, customization);
                let mut buffer = Buffer::<$cshakecore>::default();
                let mut b = [0u8; 9];

                buffer.digest_blocks(
                    left_encode(<CoreWrapper<$cshakecore> as BlockSizeUser>::BlockSize::to_u64(), &mut b),
                    |blocks| { core.update_blocks(blocks) },
                );
                buffer.digest_blocks(
                    left_encode((key.len() * 8) as u64, &mut b),
                    |blocks| { core.update_blocks(blocks) },
                );
                buffer.digest_blocks(
                    key,
                    |blocks| { core.update_blocks(blocks) },
                );
                let block = buffer.pad_with_zeros();
                core.update_blocks(slice::from_ref(&block));

                Self { digest: core }
            }
        }

        impl MacMarker for $name {}

        //todo: fix error
        impl BlockSizeUser for $name {
            type BlockSize = <$cshakecore as BlockSizeUser>::BlockSize;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                self.digest.update_blocks(blocks)
            }
        }

        impl FixedOutputCore for $name {
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                let mut b = [0u8; 9];
                buffer.digest_blocks(
                    right_encode($output_size, &mut b),
                    |blocks| { self.digest.update_blocks(blocks) },
                );
                let mut reader = self.digest.finalize_xof_core(buffer);
                reader.read(out);
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

    }
}