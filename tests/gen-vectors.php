<?php
/**
 * Generate ground-truth test vectors using PHP's hash() and crypt(),
 * which is exactly what the original mkpasswd.net site used server-side.
 *
 * Outputs: tests/vectors.json (digests), tests/crypt-vectors.json (crypt family + specials)
 */

$inputs = [
    'empty'  => '',
    'a'      => 'a',
    'abc'    => 'abc',
    'password' => 'password',
    'hello'  => 'Hello, World!',
    'utf8'   => "p\xc3\xa4ssw\xc3\xb6rd\xe2\x98\x83", // pässwörd☃
    'quick'  => 'The quick brown fox jumps over the lazy dog',
    'a55'    => str_repeat('A', 55),
    'a56'    => str_repeat('B', 56),
    'a63'    => str_repeat('C', 63),
    'a64'    => str_repeat('D', 64),
    'a65'    => str_repeat('E', 65),
    'a119'   => str_repeat('F', 119),
    'a120'   => str_repeat('G', 120),
    'a127'   => str_repeat('H', 127),
    'a128'   => str_repeat('I', 128),
    'a129'   => str_repeat('J', 129),
    'a1000'  => str_repeat('0123456789', 100),
    'bin'    => implode('', array_map('chr', range(0, 255))),
];

$algos = [
    'adler32','crc32','crc32b','crc32c',
    'fnv132','fnv1a32','fnv164','fnv1a64','joaat',
    'murmur3a','murmur3c','murmur3f',
    'xxh32','xxh64','xxh3','xxh128',
    'md2','md4','md5',
    'sha1','sha224','sha256','sha384','sha512','sha512/224','sha512/256',
    'sha3-224','sha3-256','sha3-384','sha3-512',
    'ripemd128','ripemd160','ripemd256','ripemd320',
    'whirlpool','snefru','snefru256','gost','gost-crypto',
    'tiger128,3','tiger160,3','tiger192,3','tiger128,4','tiger160,4','tiger192,4',
    'haval128,3','haval160,3','haval192,3','haval224,3','haval256,3',
    'haval128,4','haval160,4','haval192,4','haval224,4','haval256,4',
    'haval128,5','haval160,5','haval192,5','haval224,5','haval256,5',
];

$out = ['inputs' => [], 'digests' => []];
foreach ($inputs as $id => $data) {
    $out['inputs'][$id] = bin2hex($data);
}
foreach ($algos as $algo) {
    foreach ($inputs as $id => $data) {
        $out['digests'][$algo][$id] = hash($algo, $data);
    }
}
file_put_contents(__DIR__ . '/vectors.json', json_encode($out, JSON_PRETTY_PRINT));

// ---------------------------------------------------------------------------
// crypt() vectors
// ---------------------------------------------------------------------------
$cv = [];
function cv(&$cv, $type, $password, $salt) {
    $h = crypt($password, $salt);
    if ($h === false || strlen($h) < 13 || $h[0] === '*') {
        fwrite(STDERR, "crypt failed: $type / $salt\n");
        return;
    }
    $cv[] = ['type' => $type, 'password_hex' => bin2hex($password), 'salt' => $salt, 'hash' => $h];
}

$pwUtf8 = "p\xc3\xa4ssw\xc3\xb6rd";
$pw72 = str_repeat('x', 72);
$pw80 = str_repeat('y', 80);

// Traditional DES
foreach ([['password','ab'], ['password','./'], ['verylongpassword','zz'], ['a','yZ'], [$pwUtf8,'K9'], ['','Qx']] as [$p,$s]) cv($cv,'std_des',$p,$s);
// Extended DES (BSDi)
foreach ([['password','_J9..abcd'], ['password','_7C/.abcd'], ['verylongpassword_longer','_J9..SDiz'], ['a','_1234wxyz'], [$pwUtf8,'_J9..abcd']] as [$p,$s]) cv($cv,'ext_des',$p,$s);
// MD5 crypt
foreach ([['password','$1$abcdefgh$'], ['password','$1$12345678$'], ['password','$1$ab$'], ['password','$1$$'], ['password','$1$abcdefghijkl$'], [$pwUtf8,'$1$abcdefgh$'], ['a','$1$abcdefgh$'], [$pw80,'$1$abcdefgh$']] as [$p,$s]) cv($cv,'md5',$p,$s);
// Blowfish (bcrypt) — 2y / 2a / 2x, incl. 8-bit password to expose 2x sign-extension bug
$bsalt = 'abcdefghijklmnopqrstuu';
foreach (['2y','2a','2x'] as $v) {
    foreach (['password', $pwUtf8, 'a', $pw72, $pw80] as $p) {
        cv($cv, "blowfish_$v", $p, "\$$v\$04\$$bsalt");
    }
}
cv($cv, 'blowfish_2y', 'password', "\$2y\$10\$$bsalt");
// SHA-256 crypt
foreach ([['password','$5$saltstring$'], ['password','$5$rounds=10000$saltstringsaltst$'], ['password','$5$rounds=5000$abc$'], ['password','$5$abcdefghijklmnopqrstuv$'], [$pwUtf8,'$5$saltstring$'], ['a','$5$salt$'], ['password','$5$rounds=1000$short$']] as [$p,$s]) cv($cv,'sha256',$p,$s);
// SHA-512 crypt
foreach ([['password','$6$saltstring$'], ['password','$6$rounds=10000$saltstringsaltst$'], ['password','$6$rounds=5000$abc$'], ['password','$6$abcdefghijklmnopqrstuv$'], [$pwUtf8,'$6$saltstring$'], ['a','$6$salt$'], ['password','$6$rounds=1000$short$']] as [$p,$s]) cv($cv,'sha512',$p,$s);

// APR1 (Apache htpasswd MD5) via openssl
foreach ([['password','abcdefgh'], ['password','12345678'], ['a','abcdefgh'], [$pwUtf8,'abcdefgh']] as [$p,$s]) {
    $h = trim(shell_exec('openssl passwd -apr1 -salt ' . escapeshellarg($s) . ' ' . escapeshellarg($p)));
    if ($h && str_starts_with($h, '$apr1$')) {
        $cv[] = ['type' => 'apr1', 'password_hex' => bin2hex($p), 'salt' => $s, 'hash' => $h];
    } else {
        fwrite(STDERR, "openssl apr1 failed for salt $s\n");
    }
}

// ---------------------------------------------------------------------------
// Specials: nthash (MD4 over UTF-16LE), pre-MySQL-4.1 OLD_PASSWORD
// ---------------------------------------------------------------------------
$specials = ['nthash' => [], 'premysql41' => []];
foreach (['password', 'a', '', 'pässwörd', 'verylongpassword123'] as $p) {
    $specials['nthash'][bin2hex($p)] = hash('md4', iconv('UTF-8', 'UTF-16LE', $p));
}
// sanity: NTLM("password") is famously 8846f7eaee8fb117ad06bdd830b7586c
assert($specials['nthash'][bin2hex('password')] === '8846f7eaee8fb117ad06bdd830b7586c');

function old_password(string $pw): string {
    // MySQL pre-4.1 hash_password(); needs unsigned 64-bit — PHP ints overflow to
    // float, so delegate to python3
    $py = <<<'PY'
import sys
pw = bytes.fromhex(sys.argv[1])
M = 0xFFFFFFFFFFFFFFFF
nr, add, nr2 = 1345345333, 7, 0x12345671
for c in pw:
    if c in (0x20, 0x09):
        continue
    nr ^= (((nr & 63) + add) * c) + ((nr << 8) & M)
    nr &= M
    nr2 = (nr2 + (((nr2 << 8) & M) ^ nr)) & M
    add += c
print('%08x%08x' % (nr & 0x7FFFFFFF, nr2 & 0x7FFFFFFF))
PY;
    return trim(shell_exec('python3 -c ' . escapeshellarg($py) . ' ' . escapeshellarg(bin2hex($pw))));
}
if (old_password('test') !== '378b243e220ca493') {
    fwrite(STDERR, "OLD_PASSWORD sanity check FAILED: got " . old_password('test') . "\n");
    exit(1);
}
foreach (['test', 'password', 'a', '', 'longer password here', 'pässwörd'] as $p) {
    $specials['premysql41'][bin2hex($p)] = old_password($p);
}

// Argon2 (if compiled in): full encoded hashes; JS side re-derives with same salt/params
$argon = [];
if (defined('PASSWORD_ARGON2ID')) {
    $argon['argon2id'] = password_hash('password', PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);
    $argon['argon2i']  = password_hash('password', PASSWORD_ARGON2I,  ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);
}

file_put_contents(__DIR__ . '/crypt-vectors.json', json_encode([
    'crypt' => $cv,
    'specials' => $specials,
    'argon2' => $argon,
], JSON_PRETTY_PRINT));

echo "vectors.json: " . count($algos) . " algos x " . count($inputs) . " inputs\n";
echo "crypt-vectors.json: " . count($cv) . " crypt vectors, argon2: " . count($argon) . "\n";
