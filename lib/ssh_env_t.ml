type t = {
    fd: Ounix.tcp_odescr;
    log: Olog.base_log;
    rng: Cryptokit.Random.rng;
    osel: Ounix.oselect;
    kex_methods: Kex.Methods.t list;
    mac_methods: Algorithms.MAC.t list;
    cipher_methods: Algorithms.Cipher.t list;
    hostkey_algorithms: Keys.PublicKey.t list;
}

