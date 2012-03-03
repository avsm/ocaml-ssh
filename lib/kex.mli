(*
 * Copyright (c) 2004,2005 Anil Madhavapeddy <anil@recoil.org>
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
exception Key_too_short

module Methods : sig

  type t =
  | DiffieHellmanGexSHA1
  | DiffieHellmanGroup1SHA1
  | DiffieHellmanGroup14SHA1

  module DHGroup : sig
    type kex_hash = {
      v_c : Version.t;
      v_s : Version.t;
      i_c : string;
      i_s : string;
      k_s : string;
      e : Mpl_stdlib.Mpl_mpint.t;
      f : Mpl_stdlib.Mpl_mpint.t;
      k : Mpl_stdlib.Mpl_mpint.t;
    }
    val marshal : kex_hash -> string
  end

  module DHGex : sig
    type kex_hash = {
      v_c : Version.t;
      v_s : Version.t;
      i_c : string;
      i_s : string;
      k_s : string;
      min : int32;
      n : int32;
      max : int32;
      p : Mpl_stdlib.Mpl_mpint.t;
      g : Mpl_stdlib.Mpl_mpint.t;
      e : Mpl_stdlib.Mpl_mpint.t;
      f : Mpl_stdlib.Mpl_mpint.t;
      k : Mpl_stdlib.Mpl_mpint.t;
    }
    val marshal : kex_hash -> string
    type moduli
    val empty_moduli : unit -> moduli
    val add_moduli : primes:moduli -> size:int32 -> prime:Mpl_stdlib.Mpl_mpint.t ->
      generator:Mpl_stdlib.Mpl_mpint.t -> unit
    val choose : min:int32 -> want:int32 -> max:int32 -> moduli ->
      (Mpl_stdlib.Mpl_mpint.t * Mpl_stdlib.Mpl_mpint.t) option
  end

  exception Unknown of string
  val to_string : t -> string
  val from_string : string -> t

  val public_parameters : t -> Mpl_stdlib.Mpl_mpint.t * Mpl_stdlib.Mpl_mpint.t

  val algorithm_choice :
      kex:string * string ->
      enc_cs:string * string ->
      enc_sc:string * string ->
      mac_cs:string * string ->
      mac_sc:string * string ->
      (string -> exn) ->
      t * Algorithms.Cipher.t * Algorithms.Cipher.t * Algorithms.MAC.t *
      Algorithms.MAC.t
    val cryptokit_params : Mpl_stdlib.Mpl_mpint.t -> Mpl_stdlib.Mpl_mpint.t -> Cryptokit.DH.parameters
    val compute_init :
      Cryptokit.Random.rng ->
      Mpl_stdlib.Mpl_mpint.t -> Mpl_stdlib.Mpl_mpint.t -> Mpl_stdlib.Mpl_mpint.t * Cryptokit.DH.private_secret
    val compute_shared_secret :
      Mpl_stdlib.Mpl_mpint.t -> Mpl_stdlib.Mpl_mpint.t -> Cryptokit.DH.private_secret -> Mpl_stdlib.Mpl_mpint.t -> Mpl_stdlib.Mpl_mpint.t
    val compute_reply :
      Cryptokit.Random.rng -> Mpl_stdlib.Mpl_mpint.t -> Mpl_stdlib.Mpl_mpint.t -> Mpl_stdlib.Mpl_mpint.t -> Mpl_stdlib.Mpl_mpint.t * Mpl_stdlib.Mpl_mpint.t
    val pad_rsa_signature : Mpl_stdlib.Mpl_mpint.t -> string -> string
    val derive_key :
      (unit -> Cryptokit.hash) -> Mpl_stdlib.Mpl_mpint.t -> string -> string -> int -> char -> string
    val verify_rsa_signature : Message.Key.RSA.o -> string -> string -> bool
  end
