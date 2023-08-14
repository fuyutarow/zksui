module contract::verifier {
    use sui::event;
    use sui::groth16::{Self, bls12381, bn254};
    use std::vector;
    use std::debug;

    struct VerifiedEvent has copy, drop {
        is_verified: bool,
    }

    struct VerifyingKeyEvent has copy, drop {
        delta_bytes: vector<u8>,
        gamma_bytes: vector<u8>,
        alpha_bytes: vector<u8>,
        vk_bytes: vector<u8>,
    }

    struct JustEvent has copy, drop {
        vk_bytes: vector<u8>,
    }

    public entry fun verify_proof(vk: vector<u8>, public_inputs_bytes: vector<u8>, proof_points_bytes: vector<u8>) {
        let pvk = groth16::prepare_verifying_key(&groth16::bn254(), &vk);
        let public_inputs = groth16::public_proof_inputs_from_bytes(public_inputs_bytes);
        let proof_points = groth16::proof_points_from_bytes(proof_points_bytes);
        let is_verified= groth16::verify_groth16_proof(
            &groth16::bn254(),
            &pvk,
            &public_inputs,
            &proof_points,
        );

        event::emit(VerifiedEvent {
            is_verified: is_verified,
        });
    }

    public entry fun just(vk: vector<u8>) {
        use std::debug;
        debug::print(&vk);
        let arr = groth16::pvk_to_bytes(groth16::prepare_verifying_key(&bn254(), &vk));
        let delta_bytes = vector::pop_back(&mut arr);
        let gamma_bytes = vector::pop_back(&mut arr);
        let alpha_bytes = vector::pop_back(&mut arr);
        let vk_bytes = vector::pop_back(&mut arr);

        debug::print(&delta_bytes);
        debug::print(&gamma_bytes);
        debug::print(&alpha_bytes);
        debug::print(&vk_bytes);

        let expected_gamma_bytes = x"6030ca5b462a3502d560df7ff62b7f1215195233f688320de19e4b3a2a2cb6120ae49bcc0abbd3cbbf06b29b489edbf86e3b679f4e247464992145f468e3c00d";
        let expected_delta_bytes = x"b41e5e09002a7170cb4cc56ae96b152d17b6b0d1b9333b41f2325c3c8a9d2e2df98f8e2315884fae52b3c6bb329df0359daac4eff4d2e7ce729078b10d79d4af";
        let expected_alpha_bytes = x"61665b255f20b17bbd56b04a9e4d6bf596cb8d578ce5b2a9ccd498e26d394a3071485596cabce152f68889799f7f6b4e94d415c28e14a3aa609e389e344ae72778358ca908efe2349315bce79341c69623a14397b7fa47ae3fa31c6e41c2ee1b6ab50ef5434c1476d9894bc6afee68e0907b98aa8dfa3464cc9a122b247334064ff7615318b47b881cef4869f3dbfde38801475ae15244be1df58f55f71a5a01e28c8fa91fac886b97235fddb726dfc6a916483464ea130b6f82dc602e684b14f5ee655e510a0c1dd6f87b608718cd19d63a914f745a80c8016aa2c49883482aa28acd647cf9ce56446c0330fe6568bc03812b3bda44d804530abc67305f4914a509ecdc30f0b88b1a4a8b11e84856b333da3d86bb669a53dbfcde59511be60d8d5f7c79faa4910bf396ab04e7239d491e0a3bee177e6c9aac0ecbcd09ca850afcd46f25410849cefcfbdac828e7b057d4a732a373aad913d4b767897ba15d0bfcbcbb25bc5f2dae1ea59196ede9666a5c260f054b1a64977666af6a03076409";
        let expected_vk_bytes = x"1dcc52e058148a622c51acfdee6e181252ec0e9717653f0be1faaf2a68222e0dd2ccf4e1e8b088efccfdb955a1ff4a0fd28ae2ccbe1a112449ddae8738fb40b0";

        assert!(delta_bytes == expected_delta_bytes, 1003);
        assert!(gamma_bytes == expected_gamma_bytes, 1004);
        assert!(alpha_bytes == expected_alpha_bytes, 1005);
        assert!(vk_bytes == expected_vk_bytes, 1006);

        event::emit(VerifyingKeyEvent {
            delta_bytes: delta_bytes,
            gamma_bytes: gamma_bytes,
            alpha_bytes: alpha_bytes,
            vk_bytes: vk_bytes,
        });

        event::emit(JustEvent {
            vk_bytes: vk,
        });
    }

    public entry fun parse_pvk_from_vk(vk: vector<u8>) {
        use std::debug;
        debug::print(&vk);

        let arr = groth16::pvk_to_bytes(groth16::prepare_verifying_key(&bn254(), &vk));
        let delta_bytes = vector::pop_back(&mut arr);
        let gamma_bytes = vector::pop_back(&mut arr);
        let alpha_bytes = vector::pop_back(&mut arr);
        let vk_bytes = vector::pop_back(&mut arr);

        event::emit(VerifyingKeyEvent {
            delta_bytes: delta_bytes,
            gamma_bytes: gamma_bytes,
            alpha_bytes: alpha_bytes,
            vk_bytes: vk_bytes,
        })
    }

    public entry fun do_just() {
        let vk = x"53d75f472c207c7fcf6a34bc1e50cf0d7d2f983dd2230ffcaf280362d162c3871cae3e4f91b77eadaac316fe625e3764fb39af2bb5aa25007e9bc6b116f6f02f597ad7c28c4a33da5356e656dcef4660d7375973fe0d7b6dc642d51f16b6c8806030ca5b462a3502d560df7ff62b7f1215195233f688320de19e4b3a2a2cb6120ae49bcc0abbd3cbbf06b29b489edbf86e3b679f4e247464992145f468e3c08db41e5e09002a7170cb4cc56ae96b152d17b6b0d1b9333b41f2325c3c8a9d2e2df98f8e2315884fae52b3c6bb329df0359daac4eff4d2e7ce729078b10d79d42f02000000000000001dcc52e058148a622c51acfdee6e181252ec0e9717653f0be1faaf2a68222e0dd2ccf4e1e8b088efccfdb955a1ff4a0fd28ae2ccbe1a112449ddae8738fb40b0";
        just(vk);
    }

    public entry fun do_verify() {
        let vk_bytes = vector<u8>[
            180, 48, 40, 176, 123, 215, 154, 108, 134, 131, 239, 184, 172, 68, 39, 30, 32, 178, 194, 132, 224, 54, 140, 123, 196, 67, 156, 213, 187, 36, 125, 154, 138, 5, 32, 52, 238, 95, 135, 176, 162, 114, 172, 228, 205, 64, 65, 195, 96, 14, 238, 196, 128, 245, 143, 58, 142, 34, 153, 46, 57, 146, 72, 37, 152, 224, 87, 182, 36, 200, 103, 135, 142, 204, 110, 85, 38, 202, 117, 171, 160, 24, 8, 219, 154, 151, 89, 225, 64, 237, 176, 201, 31, 80, 0, 145, 105, 32, 11, 45, 32, 86, 159, 75, 158, 190, 245, 75, 177, 132, 54, 47, 25, 194, 194, 200, 18, 175, 191, 222, 132, 235, 208, 238, 244, 28, 238, 30, 5, 116, 168, 108, 147, 240, 168, 88, 7, 144, 235, 20, 83, 206, 98, 33, 112, 33, 209, 251, 229, 6, 83, 95, 217, 212, 191, 55, 151, 253, 53, 48, 89, 234, 221, 232, 155, 45, 30, 181, 155, 14, 88, 86, 167, 34, 212, 73, 26, 2, 166, 50, 160, 127, 14, 169, 140, 202, 172, 106, 89, 132, 193, 30, 156, 12, 184, 102, 155, 199, 46, 67, 75, 159, 190, 118, 43, 51, 116, 122, 116, 212, 228, 254, 199, 51, 54, 186, 212, 149, 121, 46, 189, 151, 52, 30, 2, 0, 0, 0, 0, 0, 0, 0, 244, 170, 240, 173, 151, 85, 134, 56, 224, 249, 90, 12, 18, 105, 220, 208, 198, 235, 240, 75, 126, 46, 58, 155, 143, 133, 232, 240, 71, 117, 111, 46, 231, 14, 73, 246, 165, 202, 111, 113, 97, 61, 140, 113, 163, 56, 76, 217, 44, 84, 207, 96, 231, 66, 107, 167, 21, 14, 111, 72, 71, 134, 144, 12
        ];
        let public_inputs_bytes = vector<u8>[
            1, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];
        let proof_points_bytes= vector<u8>[
            126, 49, 197, 71, 125, 182, 206, 78, 163, 129, 126, 145, 113, 111, 185, 31, 40, 190, 143, 66, 170, 70, 145, 121, 140, 184, 43, 149, 5, 146, 147, 149, 3, 20, 218, 110, 20, 130, 30, 219, 4, 49, 74, 144, 42, 24, 171, 119, 250, 48, 125, 238, 97, 122, 252, 99, 199, 241, 10, 119, 223, 177, 135, 6, 31, 171, 94, 36, 238, 173, 164, 141, 224, 200, 81, 106, 40, 222, 5, 50, 148, 210, 71, 165, 199, 151, 238, 133, 82, 197, 160, 130, 167, 90, 206, 137, 46, 194, 7, 52, 204, 44, 44, 159, 206, 65, 230, 36, 12, 106, 164, 196, 161, 66, 217, 70, 212, 207, 108, 33, 141, 42, 148, 234, 150, 219, 11, 150
        ];

        let vk = x"e8324a3242be5193eb38cca8761691ce061e89ce86f1fce8fd7ef40808f12da3c67d9ed5667c841f956e11adbbe240ddf37a1e3a4a890600dc88f608b897898e";
        debug::print(&1234567);
        debug::print(&vk);
        debug::print(&vk_bytes);

        // u256 vector<u8>

        let pvk = groth16::prepare_verifying_key(&groth16::bn254(), &vk_bytes);
        let public_inputs = groth16::public_proof_inputs_from_bytes(public_inputs_bytes);
        let proof_points = groth16::proof_points_from_bytes(proof_points_bytes);
        let is_verified= groth16::verify_groth16_proof(&groth16::bn254(), &pvk, &public_inputs, &proof_points);
        debug::print(&is_verified);
    }

    #[test]
    public entry fun test_verify() {
        do_verify()
    }

    #[test]
    public entry fun test_just() {
        do_just()
    }

    #[test]
    fun test_prepare_verifying_key_bn254() {
        let vk = x"53d75f472c207c7fcf6a34bc1e50cf0d7d2f983dd2230ffcaf280362d162c3871cae3e4f91b77eadaac316fe625e3764fb39af2bb5aa25007e9bc6b116f6f02f597ad7c28c4a33da5356e656dcef4660d7375973fe0d7b6dc642d51f16b6c8806030ca5b462a3502d560df7ff62b7f1215195233f688320de19e4b3a2a2cb6120ae49bcc0abbd3cbbf06b29b489edbf86e3b679f4e247464992145f468e3c08db41e5e09002a7170cb4cc56ae96b152d17b6b0d1b9333b41f2325c3c8a9d2e2df98f8e2315884fae52b3c6bb329df0359daac4eff4d2e7ce729078b10d79d42f02000000000000001dcc52e058148a622c51acfdee6e181252ec0e9717653f0be1faaf2a68222e0dd2ccf4e1e8b088efccfdb955a1ff4a0fd28ae2ccbe1a112449ddae8738fb40b0";
        let arr = groth16::pvk_to_bytes(groth16::prepare_verifying_key(&bn254(), &vk));

        let expected_vk_bytes = x"1dcc52e058148a622c51acfdee6e181252ec0e9717653f0be1faaf2a68222e0dd2ccf4e1e8b088efccfdb955a1ff4a0fd28ae2ccbe1a112449ddae8738fb40b0";
        let expected_alpha_bytes = x"61665b255f20b17bbd56b04a9e4d6bf596cb8d578ce5b2a9ccd498e26d394a3071485596cabce152f68889799f7f6b4e94d415c28e14a3aa609e389e344ae72778358ca908efe2349315bce79341c69623a14397b7fa47ae3fa31c6e41c2ee1b6ab50ef5434c1476d9894bc6afee68e0907b98aa8dfa3464cc9a122b247334064ff7615318b47b881cef4869f3dbfde38801475ae15244be1df58f55f71a5a01e28c8fa91fac886b97235fddb726dfc6a916483464ea130b6f82dc602e684b14f5ee655e510a0c1dd6f87b608718cd19d63a914f745a80c8016aa2c49883482aa28acd647cf9ce56446c0330fe6568bc03812b3bda44d804530abc67305f4914a509ecdc30f0b88b1a4a8b11e84856b333da3d86bb669a53dbfcde59511be60d8d5f7c79faa4910bf396ab04e7239d491e0a3bee177e6c9aac0ecbcd09ca850afcd46f25410849cefcfbdac828e7b057d4a732a373aad913d4b767897ba15d0bfcbcbb25bc5f2dae1ea59196ede9666a5c260f054b1a64977666af6a03076409";
        let expected_gamma_bytes = x"6030ca5b462a3502d560df7ff62b7f1215195233f688320de19e4b3a2a2cb6120ae49bcc0abbd3cbbf06b29b489edbf86e3b679f4e247464992145f468e3c00d";
        let expected_delta_bytes = x"b41e5e09002a7170cb4cc56ae96b152d17b6b0d1b9333b41f2325c3c8a9d2e2df98f8e2315884fae52b3c6bb329df0359daac4eff4d2e7ce729078b10d79d4af";

        let delta_bytes = vector::pop_back(&mut arr);
        assert!(delta_bytes == expected_delta_bytes, 0);

        let gamma_bytes = vector::pop_back(&mut arr);
        assert!(gamma_bytes == expected_gamma_bytes, 0);

        let alpha_bytes = vector::pop_back(&mut arr);
        assert!(alpha_bytes == expected_alpha_bytes, 0);

        let vk_bytes = vector::pop_back(&mut arr);
        assert!(vk_bytes == expected_vk_bytes, 0);


        parse_pvk_from_vk(vk);
    }

}