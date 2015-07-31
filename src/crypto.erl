-module(crypto).
-export([main/1]).

-record(crypto, {dictionary, ciphertext}).

main(Filename) ->
    Dictionary = dictionary:new("../words"),
    {ok, Ciphertext} = file:read_file(Filename),
    Ciphertext2 = binary:bin_to_list(Ciphertext),
    Crypto = new(Dictionary, Ciphertext2),
    Cipherwords = re:split(Ciphertext, "\\s+", [{return, list}]),
    Cipherwords2 = [Cw || Cw <- Cipherwords, Cw /= ""],
    solutions(Crypto, Cipherwords2).

new(Dictionary, Ciphertext) ->
    #crypto{dictionary = Dictionary, ciphertext = Ciphertext}.

solutions(This, Cipherwords) ->
    solutions(This, Cipherwords, key:new()).

solutions(_This, [], _Key) ->
    [];
solutions(This, Cipherwords, Key) ->
    Possibilities =
	[{Cw, dictionary:plainwords(This#crypto.dictionary, Cw, Key)} ||
	    Cw <- Cipherwords],
    {Cipherword, Plainwords} =
	spud:min_by(
	  Possibilities,
	  fun ({_Cipherword, Plainwords}) ->
		  erlang:length(Plainwords)
	  end),
    Cipherwords2 = Cipherwords -- [Cipherword],
    lists:flatmap(
      fun (Plainword) ->
	      Key2 = make_key(Key, Cipherword, Plainword),
	      case Cipherwords2 == [] of
		  true ->
		      output(This#crypto.ciphertext, Key2),
		      [];
		  false ->
		      solutions(This, Cipherwords2, Key2)
	      end
      end,
      Plainwords).

make_key(Key, Cipherword, Plainword) ->
    Zipped = lists:zip(Cipherword, Plainword),
    lists:foldl(
      fun ({C, P}, Accum) ->
	      key:set(Accum, C, P)
      end,
      Key,
      Zipped).

output(Ciphertext, Key) ->
    Plaintext = [key:get(Key, C) || C <- Ciphertext],
    spud:debug("~s", [Plaintext]).
