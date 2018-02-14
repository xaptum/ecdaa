#!/usr/bin/env python3

import subprocess
from sys import argv
import os
import random
import string

examples_dir = ''

class CreationException(Exception):
    pass

class JoinException(Exception):
    pass

class SignException(Exception):
    pass

class VerifyException(Exception):
    pass

class SKRevFileException(Exception):
    pass

class Issuer(object):
    def __init__(self, directory):
        if not os.path.exists(directory):
            os.mkdir(directory)
        self.directory = directory

        self.ipk_file = directory + '/ipk.bin'
        self.isk_file = directory + '/isk.bin'
        if 0 != subprocess.call([examples_dir + '/ecdaa_issuer_create_group', self.ipk_file, self.isk_file]):
            raise CreationException('****Error creating group for issuer in directory \'' + directory + '\'')

        self.nonces = dict()
        self.sk_rev_list = []

    def GetNonce(self, pk_file):
        nonce = ''.join([random.choice(string.ascii_lowercase) for i in range(32)])
        self.nonces[nonce] = pk_file
        return nonce

    def ProcessJoinRequest(self, pk_file, cred_file, cred_sig_file, nonce):
        if self.nonces.pop(nonce, None) is not pk_file:
            raise JoinException('****Issuer in directory \'' + self.directory + '\' got unknown or unmatched nonce: ' + nonce)

        if 0 != subprocess.call([examples_dir + '/ecdaa_issuer_respond_to_join_request',
                                 pk_file,
                                 self.isk_file,
                                 cred_file,
                                 cred_sig_file,
                                 nonce]):
            raise JoinException('****Issuer in directory \'' + self.directory + '\' unable to create join response')

    def AddRevokedSecretKey(self, revoked_sk_file):
        self.sk_rev_list.append(revoked_sk_file)

    def GetRevokedSecretKeyListFile(self, sk_rev_list_file):
        try:
            with open(sk_rev_list_file, 'wb') as rev_sk_list:
                for rev_sk_file in self.sk_rev_list:
                    with open(rev_sk_file, 'rb') as rev_sk_one:
                        rev_sk_list.write(rev_sk_one.read())
        except:
            raise SKRevFileException('****Issuer in directory \'' + self.directory + '\' unable to create sk_rev_list file')

class Member(object):
    def __init__(self, directory, issuer):
        if not os.path.exists(directory):
            os.mkdir(directory)
        self.directory = directory

        self.gpk_file = self.directory + '/gpk.bin'
        if 0 != subprocess.call([examples_dir + '/ecdaa_extract_group_public_key', issuer.ipk_file, self.gpk_file]):
            raise JoinException('****Error extracting group public key from file: ' + issuer.ipk_file)

        self.sk_file = self.directory + '/sk.bin'
        self.pk_file = self.directory + '/pk.bin'

        nonce = issuer.GetNonce(self.pk_file)

        if 0 != subprocess.call([examples_dir + '/ecdaa_member_request_join', nonce, self.pk_file, self.sk_file]):
            raise JoinException('****Member in directory \'' + self.directory + '\' unable to create join request')

        self.cred_file = self.directory + '/cred.bin'
        cred_sig_file = self.directory + '/cred_sig.bin'
        try:
            issuer.ProcessJoinRequest(self.pk_file, self.cred_file, cred_sig_file, 'fake-nonce')
        except JoinException as e:
            pass
        else:
            raise JoinException('Issuer should have rejected our fake nonce')
        issuer.ProcessJoinRequest(self.pk_file, self.cred_file, cred_sig_file, nonce)

        if 0 != subprocess.call([examples_dir + '/ecdaa_member_process_join_response',
                                 self.pk_file,
                                 self.gpk_file,
                                 self.cred_file,
                                 cred_sig_file]):
            print('****Error processing join response')
            exit(1)

    def Sign(self, message, sig_file):
        message_filename = examples_dir + '/msg_sign.tmp.bin'
        with open(message_filename, 'w') as message_file:
            message_file.write(message)
        if 0 != subprocess.call([examples_dir + '/ecdaa_member_sign', self.sk_file, self.cred_file, sig_file, message_filename]):
            raise SignException('****Member in directory \'' + self.directory + '\' unable to sign message: ' + message)

def Verify(message, sig_file, gpk_file, sk_rev_list_file, sk_rev_list_length):
    message_filename = examples_dir + '/msg_verify.tmp.bin'
    with open(message_filename, 'w') as message_file:
        message_file.write(message)
    if 0 != subprocess.call([examples_dir + '/ecdaa_verify', message_filename, sig_file, gpk_file, sk_rev_list_file, str(sk_rev_list_length), '', '0']):
        raise VerifyException('****Unable to verify message: ' + message)

def TestNoRevoked():
    issuer = Issuer('issuer')
    member = Member('member', issuer)
    message = 'Message'
    sig_file = 'sig.bin'
    member.Sign(message, sig_file)

    sk_rev_list_file = 'sk_rev_list.bin'
    issuer.GetRevokedSecretKeyListFile(sk_rev_list_file)
    Verify(message, sig_file, member.gpk_file, sk_rev_list_file, 0)

def TestTwoRevoked():
    issuer = Issuer('issuer_for_revs')
    member_rev1 = Member('member_rev1', issuer)
    member_rev2 = Member('member_rev2', issuer)
    member_good = Member('member_good', issuer)

    issuer.AddRevokedSecretKey(member_rev1.sk_file)
    issuer.AddRevokedSecretKey(member_rev2.sk_file)

    message1 = 'Message1'
    sig_file1 = 'sig1.bin'
    member_rev1.Sign(message1, sig_file1)

    sk_rev_list_file = 'sk_rev_list.bin'
    issuer.GetRevokedSecretKeyListFile(sk_rev_list_file)

    try:
        Verify(message1, sig_file1, member_rev1.gpk_file, sk_rev_list_file, 2)
    except VerifyException as e:
        pass
    else:
        raise VerifyException('Verify should reject a signature by a revoked member')

    message2 = 'Message2'
    sig_file2 = 'sig2.bin'
    member_rev2.Sign(message1, sig_file2)

    try:
        Verify(message2, sig_file2, member_rev2.gpk_file, sk_rev_list_file, 2)
    except VerifyException as e:
        pass
    else:
        raise VerifyException('Verify should reject a signature by a revoked member')

    message_good = 'MessageGood'
    sig_file_good = 'sig_good.bin'
    member_good.Sign(message_good, sig_file_good)
    Verify(message_good, sig_file_good, member_good.gpk_file, sk_rev_list_file, 2)

def TestWrongGroup():
    issuer1 = Issuer('issuer1')
    issuer2 = Issuer('issuer2')
    member1 = Member('member1', issuer1)
    member2 = Member('member2', issuer2)

    message = 'Message'
    sig_file = 'sig.bin'
    member2.Sign(message, sig_file)

    sk_rev_list_file = 'sk_rev_list.bin'
    issuer1.GetRevokedSecretKeyListFile(sk_rev_list_file)

    try:
        Verify(message, sig_file, member1.gpk_file, sk_rev_list_file, 0)
    except VerifyException as e:
        pass
    else:
        raise VerifyException("Verify shouldn't accept a signature from the wrong group")

if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: ' + argv[0] + ' <example-programs-directory>')
        exit(1)

    examples_dir = argv[1]

    TestNoRevoked()
    TestTwoRevoked()
    TestWrongGroup()

