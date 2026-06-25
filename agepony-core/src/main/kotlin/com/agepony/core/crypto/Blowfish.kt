package com.agepony.core.crypto

import java.security.MessageDigest

/**
 * Pure-Kotlin Blowfish primitive, with the eksblowfish key schedule needed by
 * `bcrypt_hash`. Not exposed as a general encryption API — only `expand0state`,
 * `expandstate`, and `encipher` are publicly visible because that's all
 * `BcryptPBKDF` needs.
 *
 * The π-derived P-array (18 × uint32) and four S-boxes (256 × uint32 each) are
 * Bruce Schneier's published Blowfish initialization values, transcribed exactly
 * from OpenBSD `lib/libc/crypt/blowfish.c`.
 *
 * As a safety net against transcription errors, the constants are SHA-256-fingerprinted
 * at class load time. Any tampering or typo will be caught before the first encipherment.
 */
class Blowfish {
    private val P: IntArray = P_INIT.copyOf()
    private val S: Array<IntArray> = Array(4) { S_INIT[it].copyOf() }

    /**
     * Encrypt one 64-bit block. Returns a 2-element IntArray containing the
     * encrypted (L, R) words.
     */
    fun encipher(lIn: Int, rIn: Int): IntArray {
        var L = lIn
        var R = rIn
        for (i in 0..15) {
            L = L xor P[i]
            R = R xor f(L)
            // swap
            val t = L; L = R; R = t
        }
        // undo last swap
        val t = L; L = R; R = t
        R = R xor P[16]
        L = L xor P[17]
        return intArrayOf(L, R)
    }

    private fun f(x: Int): Int {
        val a = (x ushr 24) and 0xff
        val b = (x ushr 16) and 0xff
        val c = (x ushr 8) and 0xff
        val d = x and 0xff
        return ((S[0][a] + S[1][b]) xor S[2][c]) + S[3][d]
    }

    /**
     * Eksblowfish `expand0state`: XOR `data` (cycled) into the P-array, then re-derive
     * the entire schedule by chained encipherments starting from (0, 0).
     */
    fun expand0state(data: ByteArray) {
        val reader = StreamReader(data)
        for (i in P.indices) {
            P[i] = P[i] xor reader.nextWord()
        }
        var l = 0
        var r = 0
        var i = 0
        while (i < P.size) {
            val out = encipher(l, r)
            l = out[0]; r = out[1]
            P[i] = l
            P[i + 1] = r
            i += 2
        }
        for (sbox in 0..3) {
            var k = 0
            while (k < 256) {
                val out = encipher(l, r)
                l = out[0]; r = out[1]
                S[sbox][k] = l
                S[sbox][k + 1] = r
                k += 2
            }
        }
    }

    /**
     * Eksblowfish `expandstate`: like `expand0state`, but XORs `data` (cycled) into
     * (l, r) before each encipherment in addition to the key XOR into P. Used for
     * the initial salt+passphrase mixing in `bcrypt_hash`.
     */
    fun expandstate(data: ByteArray, key: ByteArray) {
        val keyReader = StreamReader(key)
        for (i in P.indices) {
            P[i] = P[i] xor keyReader.nextWord()
        }
        val dataReader = StreamReader(data)
        var l = 0
        var r = 0
        var i = 0
        while (i < P.size) {
            l = l xor dataReader.nextWord()
            r = r xor dataReader.nextWord()
            val out = encipher(l, r)
            l = out[0]; r = out[1]
            P[i] = l
            P[i + 1] = r
            i += 2
        }
        for (sbox in 0..3) {
            var k = 0
            while (k < 256) {
                l = l xor dataReader.nextWord()
                r = r xor dataReader.nextWord()
                val out = encipher(l, r)
                l = out[0]; r = out[1]
                S[sbox][k] = l
                S[sbox][k + 1] = r
                k += 2
            }
        }
    }

    /** Reads 4 bytes BE from a cycling buffer. */
    private class StreamReader(private val data: ByteArray) {
        private var pos = 0
        fun nextWord(): Int {
            var w = 0
            for (i in 0..3) {
                w = (w shl 8) or (data[pos].toInt() and 0xff)
                pos = (pos + 1) % data.size
            }
            return w
        }
    }

    companion object {
        // P-array and S-boxes from Bruce Schneier's Blowfish paper (π-derived constants).
        // Canonical values transcribed from OpenBSD lib/libc/crypt/blowfish.c.
        // Verified at class load via SHA-256 self-check against `EXPECTED_FINGERPRINT`.

        private const val P_HEX =
            "243f6a8885a308d313198a2e03707344" +
            "a4093822299f31d0082efa98ec4e6c89" +
            "452821e638d01377be5466cf34e90c6c" +
            "c0ac29b7c97c50dd3f84d5b5b5470917" +
            "9216d5d98979fb1b"

        private const val S0_HEX =
            "d1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045f12c7f99" +
            "24a19947b3916cf70801f2e2858efc16636920d871574e69a458fea3f4933d7e" +
            "0d95748f728eb658718bcd5882154aee7b54a41dc25a59b59c30d5392af26013" +
            "c5d1b023286085f0ca417918b8db38ef8e79dcb0603a180e6c9e0e8bb01e8a3e" +
            "d71577c1bd314b2778af2fda55605c60e65525f3aa55ab945748986263e81440" +
            "55ca396a2aab10b6b4cc5c341141e8cea15486af7c72e993b3ee1411636fbc2a" +
            "2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c7a32538128958677" +
            "3b8f48986b4bb9afc4bfe81b6628219361d809ccfb21a991487cac605dec8032" +
            "ef845d5de98575b1dc262302eb651b8823893e81d396acc50f6d6ff383f44239" +
            "2e0b4482a484200469c8f04a9e1f9b5e21c66842f6e96c9a670c9c61abd388f0" +
            "6a51a0d2d8542f68960fa728ab5133a36eef0b6c137a3be4ba3bf0507efb2a98" +
            "a1f1651d39af017666ca593e82430e888cee8619456f9fb47d84a5c33b8b5ebe" +
            "e06f75d885c12073401a449f56c16aa64ed3aa62363f77061bfedf72429b023d" +
            "37d0d724d00a1248db0fead349f1c09b075372c980991b7b25d479d8f6e8def7" +
            "e3fe501ab6794c3b976ce0bd04c006bac1a94fb6409f60c45e5c9ec2196a2463" +
            "68fb6faf3e6c53b51339b2eb3b52ec6f6dfc511f9b30952ccc814544af5ebd09" +
            "bee3d004de334afd660f2807192e4bb3c0cba85745c8740fd20b5f39b9d3fbdb" +
            "5579c0bd1a60320ad6a100c6402c7279679f25fefb1fa3cc8ea5e9f8db3222f8" +
            "3c7516dffd616b152f501ec8ad0552ab323db5fafd23876053317b483e00df82" +
            "9e5c57bbca6f8ca01a87562edf1769dbd542a8f6287effc3ac6732c68c4f5573" +
            "695b27b0bbca58c8e1ffa35db8f011a010fa3d98fd2183b84afcb56c2dd1d35b" +
            "9a53e479b6f84565d28e49bc4bfb9790e1ddf2daa4cb7e3362fb1341cee4c6e8" +
            "ef20cada36774c01d07e9efe2bf11fb495dbda4dae909198eaad8e716b93d5a0" +
            "d08ed1d0afc725e08e3c5b2f8e7594b78ff6e2fbf2122b648888b812900df01c" +
            "4fad5ea0688fc31cd1cff191b3a8c1ad2f2f2218be0e1777ea752dfe8b021fa1" +
            "e5a0cc0fb56f74e818acf3d6ce89e299b4a84fe0fd13e0b77cc43b81d2ada8d9" +
            "165fa2668095770593cc7314211a1477e6ad206577b5fa86c75442f5fb9d35cf" +
            "ebcdaf0c7b3e89a0d6411bd3ae1e7e4900250e2d2071b35e226800bb57b8e0af" +
            "2464369bf009b91e5563911d59dfa6aa78c14389d95a537f207d5ba202e5b9c5" +
            "832603766295cfa911c819684e734a41b3472dca7b14a94a1b5100529a532915" +
            "d60f573fbc9bc6e42b60a47681e6740008ba6fb5571be91ff296ec6b2a0dd915" +
            "b6636521e7b9f9b6ff34052ec585566453b02d5da99f8fa108ba47996e85076a"

        private const val S1_HEX =
            "4b7a70e9b5b32944db75092ec4192623ad6ea6b049a7df7d9cee60b88fedb266" +
            "ecaa8c71699a17ff5664526cc2b19ee1193602a575094c29a0591340e4183a3e" +
            "3f54989a5b429d656b8fe4d699f73fd6a1d29c07efe830f54d2d38e6f0255dc1" +
            "4cdd20868470eb266382e9c6021ecc5e09686b3f3ebaefc93c9718146b6a70a1" +
            "687f358452a0e286b79c5305aa5007373e07841c7fdeae5c8e7d44ec5716f2b8" +
            "b03ada37f0500c0df01c1f040200b3ffae0cf51a3cb574b225837a58dc0921bd" +
            "d19113f97ca92ff69432477322f547013ae5e58137c2dadcc8b576349af3dda7" +
            "a94461460fd0030eecc8c73ea4751e41e238cd993bea0e2f3280bba1183eb331" +
            "4e548b384f6db9086f420d03f60a04bf2cb8129024977c795679b072bcaf89af" +
            "de9a771fd9930810b38bae12dccf3f2e5512721f2e6b7124501adde69f84cd87" +
            "7a5847187408da17bc9f9abce94b7d8cec7aec3adb851dfa63094366c464c3d2" +
            "ef1c18473215d908dd433b3724c2ba1612a14d432a65c45150940002133ae4dd" +
            "71dff89e10314e5581ac77d65f11199b043556f1d7a3c76b3c11183b5924a509" +
            "f28fe6ed97f1fbfa9ebabf2c1e153c6e86e34570eae96fb1860e5e0a5a3e2ab3" +
            "771fe71c4e3d06fa2965dcb999e71d0f803e89d65266c8252e4cc9789c10b36a" +
            "c6150eba94e2ea78a5fc3c531e0a2df4f2f74ea7361d2b3d1939260f19c27960" +
            "5223a708f71312b6ebadfe6eeac31f66e3bc4595a67bc883b17f37d1018cff28" +
            "c332ddefbe6c5aa56558218568ab9802eecea50fdb2f953b2aef7dad5b6e2f84" +
            "1521b62829076170ecdd4775619f151013cca830eb61bd960334fe1eaa0363cf" +
            "b5735c904c70a239d59e9e0bcbaade14eecc86bc60622ca79cab5cabb2f3846e" +
            "648b1eaf19bdf0caa02369b9655abb5040685a323c2ab4b3319ee9d5c021b8f7" +
            "9b540b19875fa09995f7997e623d7da8f837889a97e32d7711ed935f16681281" +
            "0e358829c7e61fd696dedfa17858ba9957f584a51b2272639b83c3ff1ac24696" +
            "cdb30aeb532e30548fd948e46dbc312858ebf2ef34c6ffeafe28ed61ee7c3c73" +
            "5d4a14d9e864b7e342105d14203e13e045eee2b6a3aaabeadb6c4f15facb4fd0" +
            "c742f442ef6abbb5654f3b1d41cd2105d81e799e86854dc7e44b476a3d816250" +
            "cf62a1f25b8d2646fc8883a0c1c7b6a37f1524c369cb749247848a0b5692b285" +
            "095bbf00ad19489d1462b17423820e0058428d2a0c55f5ea1dadf43e233f7061" +
            "3372f0928d937e41d65fecf16c223bdb7cde3759cbee74604085f2a7ce77326e" +
            "a607808419f8509ee8efd85561d99735a969a7aac50c06c25a04abfc800bcadc" +
            "9e447a2ec3453484fdd567050e1e9ec9db73dbd3105588cd675fda79e3674340" +
            "c5c43465713e38d83d28f89ef16dff20153e21e78fb03d4ae6e39f2bdb83adf7"

        private const val S2_HEX =
            "e93d5a68948140f7f64c261c94692934411520f77602d4f7bcf46b2ed4a20068" +
            "d40824713320f46a43b7d4b7500061af1e39f62e9724454614214f74bf8b8840" +
            "4d95fc1d96b591af70f4ddd366a02f45bfbc09ec03bd97857fac6dd031cb8504" +
            "96eb27b355fd3941da2547e6abca0a9a28507825530429f40a2c86dae9b66dfb" +
            "68dc1462d7486900680ec0a427a18dee4f3ffea2e887ad8cb58ce0067af4d6b6" +
            "aace1e7cd3375fecce78a399406b2a4220fe9e35d9f385b9ee39d7ab3b124e8b" +
            "1dc9faf74b6d185626a36631eae397b23a6efa74dd5b43326841e7f7ca7820fb" +
            "fb0af54ed8feb397454056acba48952755533a3a20838d87fe6ba9b7d096954b" +
            "55a867bca1159a58cca9296399e1db33a62a4a563f3125f95ef47e1c9029317c" +
            "fdf8e80204272f7080bb155c05282ce395c11548e4c66d2248c1133fc70f86dc" +
            "07f9c9ee41041f0f404779a45d886e17325f51ebd59bc0d1f2bcc18f41113564" +
            "257b7834602a9c60dff8e8a31f636c1b0e12b4c202e1329eaf664fd1cad18115" +
            "6b2395e0333e92e13b240b62eebeb92285b2a20ee6ba0d99de720c8c2da2f728" +
            "d012784595b794fd647d0862e7ccf5f05449a36f877d48fac39dfd27f33e8d1e" +
            "0a476341992eff743a6f6eabf4f8fd37a812dc60a1ebddf8991be14cdb6e6b0d" +
            "c67b55106d672c372765d43bdcd0e804f1290dc7cc00ffa3b5390f92690fed0b" +
            "667b9ffbcedb7d9ca091cf0bd9155ea3bb132f88515bad247b9479bf763bd6eb" +
            "37392eb3cc1159798026e297f42e312d6842ada7c66a2b3b12754ccc782ef11c" +
            "6a124237b79251e706a1bbe64bfb63501a6b101811caedfa3d25bdd8e2e1c3c9" +
            "444216590a121386d90cec6ed5abea2a64af674eda86a85fbebfe98864e4c3fe" +
            "9dbc8057f0f7c08660787bf86003604dd1fd8346f6381fb07745ae04d736fccc" +
            "83426b33f01eab71b08041873c005e5f77a057bebde8ae2455464299bf582e61" +
            "4e58f48ff2ddfda2f474ef388789bdc25366f9c3c8b38e74b475f25546fcd9b9" +
            "7aeb26618b1ddf84846a0e79915f95e2466e598e20b457708cd55591c902de4c" +
            "b90bace1bb8205d011a862487574a99eb77f19b6e0a9dc09662d09a1c4324633" +
            "e85a1f0209f0be8c4a99a0251d6efe101ab93d1d0ba5a4dfa186f20f2868f169" +
            "dcb7da83573906fea1e2ce9b4fcd7f5250115e01a70683faa002b5c40de6d027" +
            "9af88c27773f8641c3604c0661a806b5f0177a28c0f586e0006058aa30dc7d62" +
            "11e69ed72338ea6353c2dd94c2c21634bbcbee5690bcb6deebfc7da1ce591d76" +
            "6f05e4094b7c018839720a3d7c927c2486e3725f724d9db91ac15bb4d39eb8fc" +
            "ed54557808fca5b5d83d7cd34dad0fc41e50ef5eb161e6f8a28514d96c51133c" +
            "6fd5c7e756e14ec4362abfceddc6c837d79a323492638212670efa8e406000e0"

        private const val S3_HEX =
            "3a39ce37d3faf5cfabc277375ac52d1b5cb0679e4fa33742d382274099bc9bbe" +
            "d5118e9dbf0f7315d62d1c7ec700c47bb78c1b6b21a19045b26eb1be6a366eb4" +
            "5748ab2fbc946e79c6a376d26549c2c8530ff8ee468dde7dd5730a1d4cd04dc6" +
            "2939bbdba9ba4650ac9526e8be5ee304a1fad5f06a2d519a63ef8ce29a86ee22" +
            "c089c2b843242ef6a51e03aa9cf2d0a483c061ba9be96a4d8fe51550ba645bd6" +
            "2826a2f9a73a3ae14ba99586ef5562e9c72fefd3f752f7da3f046f6977fa0a59" +
            "80e4a91587b086019b09e6ad3b3ee593e990fd5a9e34d7972cf0b7d9022b8b51" +
            "96d5ac3a017da67dd1cf3ed67c7d2d281f9f25cfadf2b89b5ad6b4725a88f54c" +
            "e029ac71e019a5e647b0acfded93fa9be8d3c48d283b57ccf8d5662979132e28" +
            "785f0191ed756055f7960e44e3d35e8c15056dd488f46dba03a161250564f0bd" +
            "c3eb9e153c9057a297271aeca93a072a1b3f6d9b1e6321f5f59c66fb26dcf319" +
            "7533d928b155fdf5035634828aba3cbb28517711c20ad9f8abcc5167ccad925f" +
            "4de817513830dc8e379d58629320f991ea7a90c2fb3e7bce5121ce64774fbe32" +
            "a8b6e37ec3293d4648de53696413e680a2ae0810dd6db22469852dfd09072166" +
            "b39a460a6445c0dd586cdecf1c20c8ae5bbef7dd1b588d40ccd2017f6bb4e3bb" +
            "dda26a7e3a59ff453e350a44bcb4cdd572eacea8fa6484bb8d6612aebf3c6f47" +
            "d29be463542f5d9eaec2771bf64e6370740e0d8de75b1357f8721671af537d5d" +
            "4040cb084eb4e2cc34d2466a0115af84e1b0042895983a1d06b89fb4ce6ea048" +
            "6f3f3b823520ab82011a1d4b277227f8611560b1e7933fdcbb3a792b344525bd" +
            "a08839e151ce794b2f32c9b7a01fbac9e01cc87ebcc7d1f6cf0111c3a1e8aac7" +
            "1a908749d44fbd9ad0dadecbd50ada380339c32ac69136678df9317ce0b12b4f" +
            "f79e59b743f5bb3af2d519ff27d9459cbf97222c15e6fc2a0f91fc719b941525" +
            "fae59361ceb69cebc2a8645912baa8d1b6c1075ee3056a0c10d25065cb03a442" +
            "e0ec6e0e1698db3b4c98a0be3278e9649f1f9532e0d392dfd3a0342b8971f21e" +
            "1b0a74414ba3348cc5be7120c37632d8df359f8d9b992f2ee60b6f470fe3f11d" +
            "e54cda541edad891ce6279cfcd3e7e6f1618b166fd2c1d05848fd2c5f6fb2299" +
            "f523f357a632762393a8353156cccd02acf081625a75ebb56e16369788d273cc" +
            "de96629281b949d04c50901b71c65614e6c6c7bd327a140a45e1d006c3f27b9a" +
            "c9aa53fd62a80f00bb25bfe235bdd2f671126905b2040222b6cbcf7ccd769c2b" +
            "53113ec01640e3d338abbd602547adf0ba38209cf746ce7677afa1c520756060" +
            "85cbfe4e8ae88dd87aaaf9b04cf9aa7e1948c25c02fb8a8c01c36ae4d6ebe1f9" +
            "90d4f869a65cdea03f09252dc208e69fb74e6132ce77e25b578fdfe33ac372e6"

        /**
         * SHA-256 of the canonical P || S0 || S1 || S2 || S3 with each uint32 packed
         * as 4 big-endian bytes (4168 bytes total). Computed against the OpenBSD
         * blowfish.c reference values. Any typo in the hex blobs above will cause
         * `checkFingerprint()` to throw at class load.
         */
        private const val EXPECTED_FINGERPRINT =
            "b5643208907b11b20e499a42187dc921f9579d28dadfccbe69a5ce232a55952f"

        private val P_INIT: IntArray = hexToInts(P_HEX, 18)
        private val S_INIT: Array<IntArray> = arrayOf(
            hexToInts(S0_HEX, 256),
            hexToInts(S1_HEX, 256),
            hexToInts(S2_HEX, 256),
            hexToInts(S3_HEX, 256),
        )

        init {
            checkFingerprint()
        }

        private fun checkFingerprint() {
            val md = MessageDigest.getInstance("SHA-256")
            val packed = ByteArray(4 * (P_INIT.size + S_INIT.sumOf { it.size }))
            var off = 0
            for (v in P_INIT) {
                packed[off]     = (v ushr 24).toByte()
                packed[off + 1] = (v ushr 16).toByte()
                packed[off + 2] = (v ushr 8).toByte()
                packed[off + 3] = v.toByte()
                off += 4
            }
            for (sbox in S_INIT) {
                for (v in sbox) {
                    packed[off]     = (v ushr 24).toByte()
                    packed[off + 1] = (v ushr 16).toByte()
                    packed[off + 2] = (v ushr 8).toByte()
                    packed[off + 3] = v.toByte()
                    off += 4
                }
            }
            val digest = md.digest(packed)
            val fp = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
            check(fp == EXPECTED_FINGERPRINT) {
                "Blowfish constants corrupted: SHA-256=$fp expected=$EXPECTED_FINGERPRINT"
            }
        }

        private fun hexToInts(hex: String, expectedCount: Int): IntArray {
            require(hex.length == expectedCount * 8) {
                "expected ${expectedCount * 8} hex chars, got ${hex.length}"
            }
            val out = IntArray(expectedCount)
            for (i in 0 until expectedCount) {
                val start = i * 8
                var v = 0L
                for (j in 0 until 8) {
                    val c = hex[start + j]
                    val d = when (c) {
                        in '0'..'9' -> c.code - '0'.code
                        in 'a'..'f' -> c.code - 'a'.code + 10
                        else -> throw IllegalArgumentException("bad hex char '$c'")
                    }
                    v = (v shl 4) or d.toLong()
                }
                out[i] = v.toInt()
            }
            return out
        }
    }
}
