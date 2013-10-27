module type ARBITRARY_HEADERS = sig
  include Semantics.HEADERS
  val all_headers : header list
  val arbitrary_header : header QuickCheck.arbitrary
  val arbitrary_headerval : value QuickCheck.arbitrary
  val arbitrary_payload : payload QuickCheck.arbitrary  
end

module type S = sig
  type policy
  type packet
  val arbitrary_link : policy QuickCheck.arbitrary
  val arbitrary_lf_policy : policy QuickCheck.arbitrary
  val arbitrary_policy : policy QuickCheck.arbitrary
  val arbitrary_packet : packet QuickCheck.arbitrary
end

module Make
  (Syntax : Semantics.S)
  (Headers : ARBITRARY_HEADERS
     with type header = Syntax.header
      and type value = Syntax.header_val
      and type payload = Syntax.payload) :
    S with type policy = Syntax.policy
       and type packet = Syntax.packet = struct

  type packet = Syntax.packet
  type policy = Syntax.policy

  open Syntax
  open Headers

  let treesize n x =
    if n <= 0
      then x
      else QuickCheck_gen.resize (n / (1 + Random.int n)) x

  let gen_atom_pred : pred QuickCheck_gen.gen = 
    let open QuickCheck_gen in 
      arbitrary_header >>= fun h ->
        arbitrary_headerval >>= fun v ->
          ret_gen (Test (h, v))

  let rec gen_composite_pred () : pred QuickCheck_gen.gen =
    let open QuickCheck_gen in
      sized (fun n -> treesize n
        (frequency [
            (3, gen_pred_ctor () >>= fun pr1 ->
                  gen_pred_ctor () >>= fun pr2 ->
                    ret_gen (And (pr1, pr2)));
            (3, gen_pred_ctor () >>= fun pr1 ->
                  gen_pred_ctor () >>= fun pr2 ->
                    ret_gen (Or (pr1, pr2)));
            (1, gen_pred_ctor () >>= fun pr ->
                  ret_gen (Neg (pr)))
          ]))

  and gen_pred_ctor () : pred QuickCheck_gen.gen =
    let open QuickCheck_gen in
      sized (fun n -> treesize n
        (frequency [ (1, gen_atom_pred);
                     (max 0 (n - 1), gen_composite_pred ())
                   ]))

  let gen_pred : pred QuickCheck_gen.gen =
    let open QuickCheck_gen in
      frequency [
        (1, ret_gen (True));
        (1, ret_gen (False));
        (* XXX(seliopou) this should be a function of the size. *)
        (3, gen_pred_ctor ())
        ]

  let arbitrary_link : policy QuickCheck_gen.gen = 
    let open QuickCheck_gen in
    arbitrary_headerval >>= fun sw1 ->
    arbitrary_headerval >>= fun pt1 ->
    arbitrary_headerval >>= fun sw2 ->
    arbitrary_headerval >>= fun pt2 ->
      ret_gen (Link(sw1,pt1,sw2,pt2))

  let gen_lf_atom_pol : policy QuickCheck_gen.gen  =
    let open QuickCheck_gen in
    oneof [
      (arbitrary_header >>= fun h -> 
        arbitrary_headerval >>= fun v ->
           ret_gen (Mod (h, v)));
      (gen_pred >>= fun pr ->
          ret_gen (Filter (pr))) ]

  let gen_atom_pol : policy QuickCheck_gen.gen = 
    let open QuickCheck_gen in
    oneof [
      (arbitrary_header >>= fun h -> 
        arbitrary_headerval >>= fun v ->
           ret_gen (Mod (h, v)));
      (gen_pred >>= fun pr ->
          ret_gen (Filter (pr)));
      arbitrary_link ]


  let rec gen_composite_pol arbitrary_atom : policy QuickCheck_gen.gen =
    let open QuickCheck_gen in 
        sized (fun n -> treesize n
         (frequency [
            (3, gen_pol arbitrary_atom >>= fun p1 ->
                gen_pol arbitrary_atom >>= fun p2 ->
                ret_gen (Par (p1, p2)));
            (3, gen_pol arbitrary_atom>>= fun p1 ->
                gen_pol arbitrary_atom >>= fun p2 ->
                ret_gen (Seq (p1, p2)));
            (1, gen_pol arbitrary_atom >>= fun p ->
                ret_gen (Star p))
          ]))

  and gen_pol arbitrary_atom : policy QuickCheck_gen.gen =
    let open QuickCheck_gen in
      sized (fun n ->
        frequency [
            (1, arbitrary_atom);
            (max 0 (n - 1), gen_composite_pol arbitrary_atom) ])


  let arbitrary_policy = gen_pol gen_atom_pol
  let arbitrary_lf_policy = gen_pol gen_lf_atom_pol

  let num_hdrs = List.length all_headers

  let arbitrary_packet : packet QuickCheck_gen.gen = 
    let open QuickCheck_gen in
    let open QuickCheck in
    listN num_hdrs arbitrary_headerval >>= fun vals ->
      arbitrary_payload >>= fun payload ->
      ret_gen {
        headers = List.fold_right2 HeaderMap.add all_headers vals HeaderMap.empty;
        payload = payload
      }

end

module SDNHeaders = struct
  include SDN_Headers

  let all_headers = 
    [
    (Header (SDN_Types.InPort));
    (Header (SDN_Types.EthType));
    (Header (SDN_Types.EthSrc));
    (Header (SDN_Types.EthDst));
    (Header (SDN_Types.Vlan));
    (Header (SDN_Types.IPProto));
    (Header (SDN_Types.IP4Src));
    (Header (SDN_Types.IP4Dst));
    (Header (SDN_Types.TCPSrcPort));
    (Header (SDN_Types.TCPDstPort));
    Switch
  ] 

  let arbitrary_header  = 
    let open QuickCheck_gen in
    elements all_headers

  let arbitrary_headerval =
    let open QuickCheck_gen in 
    choose_int0 200 >>= fun rint ->
    ret_gen (VInt.Int64 (Int64.of_int rint))

  let arbitrary_payload = QuickCheck_gen.Gen (fun _ -> failwith "SDNHeaders.arbitrary_payload NYI")

end

module SDNArb = Make (NetKAT_Types) (SDNHeaders)

let arbitrary_link = SDNArb.arbitrary_link
let arbitrary_lf_pol = SDNArb.arbitrary_lf_policy
let arbitrary_pol = SDNArb.arbitrary_policy
