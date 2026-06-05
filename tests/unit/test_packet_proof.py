#!/usr/bin/env python3
import unittest

from scripts import packet_proof


class PacketProofTests(unittest.TestCase):
    def test_build_proof_from_tc_chat_output(self):
        stdout = (
            '{"type":"packet","action":"encrypt","sample":"aabbcc"}\n'
            '{"type":"packet","action":"decrypt","sample":"68656c6c6f207265616c206170700202"}\n'
            "tc udp chat crypto passed\n"
        )

        proof = packet_proof.build_proof(stdout)

        self.assertEqual(proof["plaintext"], "hello real app")
        self.assertEqual(proof["encrypted_sample_hex"], "aabbcc")
        self.assertEqual(proof["decrypted_sample_hex"], "68656c6c6f207265616c206170700202")
        self.assertTrue(proof["ciphertext_differs"])
        self.assertTrue(proof["decrypt_matches"])


if __name__ == "__main__":
    unittest.main()
