
let scenario_regex_str = "\\([0-9]+\\)"
let memory_regex_str = "\\([0-9]+\\)"
let time_regex_str = "\\([0-9:\\.]+\\)"
let path_regex_str = "\\([a-zA-Z_0-9]+\\)"
let time_memory_regex_str = Printf.sprintf "%s - Scenario F%s S%s B%s A%s - [0-9]+ true queries - Time %s - Memory %sk\\( Command terminated by signal 9\\)?"
  path_regex_str
  scenario_regex_str
  scenario_regex_str
  scenario_regex_str
  scenario_regex_str
  time_regex_str memory_regex_str
let regex_time_memory_result = Str.regexp time_memory_regex_str


type tm_entry =
  { time : int; (* In seconds *)
    memory : int (* In MB *)
  }

type result_tm_entry =
  {
    file : string;
    sc_F : int;
    sc_S : int;
    sc_B : int;
    sc_A : int;
    time : int; (* In seconds *)
    memory : int (* In MB *)
  }

let time_hours_regex = Str.regexp "\\([0-9]+\\):\\([0-9]+\\):\\([0-9]+\\)"
let time_min_regex = Str.regexp "\\([0-9]+\\):\\([0-9]+\\)\\.\\([0-9]+\\)"

let second_of str =
  if Str.string_match time_hours_regex str 0
  then
    let hours = Str.matched_group 1 str in
    let mins = Str.matched_group 2 str in
    let secs = Str.matched_group 3 str in
    (int_of_string secs) + 60 * (int_of_string mins) + 3600 * (int_of_string hours)
  else if Str.string_match time_min_regex str 0
  then
    let mins = Str.matched_group 1 str in
    let secs = Str.matched_group 2 str in
    let milisec = Str.matched_group 3 str in
    if int_of_string milisec >= 50
    then (int_of_string secs) + 60 * (int_of_string mins) + 1
    else (int_of_string secs) + 60 * (int_of_string mins)
  else failwith "[Unexpected time format]"

let memory_of str =
  let kilos = int_of_string str in
  kilos / 1000

let database = ref []

let add path sc_F sc_S sc_B sc_A time memory error =
  let tm_entry =
    {
      file = path;
      sc_F = int_of_string sc_F;
      sc_S = int_of_string sc_S;
      sc_B = int_of_string sc_B;
      sc_A = int_of_string sc_A;
      time = if error then - second_of time else second_of time;
      memory = if error then - memory_of memory else memory_of memory
    } in

  database := tm_entry :: !database

let display_time e =
  let e_display = if e.time < 0 then -e.time else e.time in
  let e_neg = if e.time < 0 then "-" else "" in
      let mins = e_display/60 in
      let sec = e_display - mins * 60 in
      Printf.sprintf "%s%d:%d" e_neg mins sec

let display_memory e = string_of_int e.memory

(* In order:
    - lemma
    - secrecy
    - authentication
    - early data
    - PH Data
    - PH authentication
    - downgrade
    - key_sequentiality
    - psk_or_random
    - privacy_backend
    - anonymity_unlinkability_TLS_client
    - anonymity_unlinkability_ECH_client
    - strong_secrecy_ee
    - strong_secrecy_inner
 *)

let list_security_properties =
  [
    ("lemmas_reachability","Lemmas");
    ("secrecy","Secrecy");
    ("authentication","Auth");
    ("early_data","0RTT Data");
    ("post_handshake_data","PH Data");
    ("post_handshake_authentication","PH Auth");
    ("downgrade_resilient_ech","Downgrade");
    ("key_sequentiality","Keys");
    ("psk_or_random","PoR");
    ("privacy_backend","Backend Privacy");
    ("anonymity_unlinkability_TLS_client","TLS Privacy");
    ("anonymity_unlinkability_ECH_client","ECH Privacy");
    ("strong_secrecy_ee","EE Secrecy");
    ("strong_secrecy_inner","Inner Secrecy")
  ]

let display_one_line for_time scF scS scB scA =
  let lookup file =
    try
      let entry = List.find (fun entry -> entry.file = file && entry.sc_F = scF && entry.sc_S = scS && entry.sc_B = scB && entry.sc_A = scA) !database in
      if for_time
      then display_time entry
      else display_memory entry
    with Not_found -> ""
  in
  Printf.printf "%d;%d;%d;%d" scF scS scB scA;
  List.iter (fun (secu_prop,_) -> Printf.printf ";%s" (lookup secu_prop)) list_security_properties;
  print_string "\n"

let read_file path_file =
  if Sys.file_exists path_file
  then
  let channel_in = open_in path_file in

  begin
    try
      while true do
        let l = input_line channel_in in
        if l <> "" && Str.string_match regex_time_memory_result l 0
        then
          let path = Str.matched_group 1 l in
          let sc_F =  Str.matched_group 2 l in
          let sc_S =  Str.matched_group 3 l in
          let sc_B =  Str.matched_group 4 l in
          let sc_A =  Str.matched_group 5 l in
          let time = Str.matched_group 6 l in
          let memory = Str.matched_group 7 l in
          let error =
            try
              let _ = Str.matched_group 8 l in
              true
            with Not_found -> false
          in
          add path sc_F sc_S sc_B sc_A time memory error
        else
          Printf.printf "Not recognized: %s\n" l
      done
    with End_of_file -> ()
  end

(* RESULT *)

let display_database () =
  let display for_time =
    print_string "----------------\n";
    Printf.printf "F;S;B;A";
    List.iter (fun (_,secu_prop) -> Printf.printf ";%s" secu_prop) list_security_properties;
    print_string "\n";
    for f = 1 to 10 do
      for s = 1 to 3 do
        for b = 1 to 3 do
          for a = 1 to 4 do
            display_one_line for_time f s b a
          done
        done
      done
    done
  in
  display true;
  print_string "\n\n";
  display false

let _ =
  List.iter (fun (secu_prop,_) ->
    read_file (Printf.sprintf "security_properties/%s/result.txt" secu_prop)
  ) list_security_properties;

  display_database ()
