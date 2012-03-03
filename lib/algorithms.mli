(*
 * Copyright (c) 2004 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

exception Not_implemented
module Cipher : sig
  type t =
    | TripleDES_CBC
    | AES_256_CBC
    | AES_192_CBC
    | AES_128_CBC
    | Arcfour
    | None
  type mode = Encrypt | Decrypt
  type info = { name : t; key_len : int; block_size : int; }
  type fn =
    | Stream of Cryptokit.Stream.stream_cipher
    | Block of Cryptokit.Block.block_cipher
  exception Unknown of string
  val to_string : t -> string
  val from_string : string -> t
  val info : t -> info
  val fn : string -> string -> t -> mode -> fn
  val data : fn -> string -> int -> string -> int -> int -> unit
end

module MAC : sig
  type t =
    | SHA1
    | SHA1_96 
    | MD5 
    | MD5_96 
    | None

  type info = {
    name : t;
    digest_len : int;
    key_len : int;
    fn : string -> Cryptokit.hash;
  }

  exception Unknown of string

  val to_string : t -> string
  val from_string : string -> t

  val null_mac : string -> Cryptokit.hash
  val info : t -> info
  val generate : info -> int32 ref -> string -> string -> int -> int -> string
end
