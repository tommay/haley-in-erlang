-module(crypto).
-export([main/1]).

main(Filename) ->
    Dictionary = load_dictionary("../words"),
    Ciphertext = load_ciphertext(Filename),
    solve(Ciphertext, Dictionary).

%% Returns a list of dictionary words, as binaries.
%%
load_dictionary(Filename) ->
    {ok, Raw} = file:read_file(Filename),
    Words = re:split(Raw, "\\n"),
    [W || W <- Words,
	  re:run(W, "[A-Z]") == nomatch].

%% Returns the ciphertext, as a string.
%%
load_ciphertext(Filename) ->
    {ok, Ciphertext} = file:read_file(Filename),
    re:replace(Ciphertext, "#.*\n", "", [global, {return, list}]).

solve(Ciphertext, Dictionary) ->
    Cw = re:split(Ciphertext, "\\s+", [{return, list}]),
    Cw2 = [W || W <- Cw, W /= ""],
    Cipherwords = [word:new(W, Dictionary) || W <- Cw2],
    solutions(Ciphertext, Cipherwords).

solutions(Ciphertext, Cipherwords) ->
    solutions(Ciphertext, Cipherwords, key:new()).

solutions(_Ciphertext, [], _Key) ->
    [];
solutions(Ciphertext, Cipherwords, Key) ->
    Cipherword = spud:min_by(
		   Cipherwords,
		   fun(Cw) -> word:dictionary_size(Cw) end),

    lists:flatmap(
      fun (Plainword) ->
	      case augment_key(Key, word:cipherword(Cipherword), Plainword) of
		  none ->
		      [];
		  NewKey ->
		      case erlang:length(Cipherwords) == 1 of
			  true ->
			      output(Ciphertext, NewKey),
			      []; %% [NewKey];
			  false ->
			      NewCipherwords = [word:filter(W, NewKey) ||
						   W <- Cipherwords,
						   W /= Cipherword],
			      solutions(Ciphertext, NewCipherwords, NewKey)
		      end
	      end
      end,
      word:dictionary(Cipherword)).

%% Given a cipherword and the plainword we are tentatively matching it
%% to, return a new key based on the given key with
%% cipherword->plainword letters filled in.  Return nil if it's not
%% possible to make such a key because to cipher letters would need to
%% map to the same plain letter.
%%
augment_key(Key, Cipherword, Plainword) ->
    %% Don't allow the same plaintext letter to be mapped by two
    %% different ciphertext letters.  The regexp matching prevents a
    %% ciphertext letter from matching two different plaintext
    %% letters.
    InvertedKey = key:invert(Key),
    Zipped = lists:zip(Cipherword, binary:bin_to_list(Plainword)),
    IKey2 = lists:foldl(
	      fun (_, none) ->
		      none;
		  ({C, P}, Accum) ->
		      %% Is there already a mapping to this plaintext letter?
		      case key:get(Accum, P) of
			  unknown ->
			      %% No.
			      key:set(Accum, P, C);
			  C ->
			      %% P is already mapped by C.
			      Accum;
			  _ ->
			      %% P is already mapped by a different
			      %% cipher letter.
			      none
		      end
	      end,
	      InvertedKey,
	      Zipped),
    case IKey2 of
	none ->
	    none;
	_ ->
	    key:invert(IKey2)
    end.

output(Ciphertext, Key) ->
    Plaintext = [key:get(Key, C) || C <- Ciphertext],
    spud:debug("~s", [Plaintext]).
