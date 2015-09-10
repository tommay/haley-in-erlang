-module(crypto).
-export([main/1]).

%% Decrypts the contents of Filename, printing any solutions to stdout
%% as they're found.  We could just accumulate the solution keys in a list,
%% but sometimes that takes a long time.
%%
main(Filename) ->
    Dictionary = load_dictionary("../words"),
    Ciphertext = load_ciphertext(Filename),
    solve(Ciphertext, Dictionary).

%% Returns a list of dictionary words, as binaries.  Words with
%% capital leters are removed.
%%
load_dictionary(Filename) ->
    {ok, Raw} = file:read_file(Filename),
    Words = re:split(Raw, "\\n"),
    [W || W <- Words,
	  re:run(W, "[A-Z]") == nomatch].

%% Returns the ciphertext, as a string.  Hash comments are removed.
%%
load_ciphertext(Filename) ->
    {ok, Ciphertext} = file:read_file(Filename),
    re:replace(Ciphertext, "#.*\n", "", [global, {return, list}]).

%% Prints out all solutions for Ciphertext (string) using the words in
%% Dictionary (list of binaries).  solve just massages things and
%% hands off to solutions to do the real work.
%%
solve(Ciphertext, Dictionary) ->
    Cw = re:split(Ciphertext, "\\s+", [{return, list}]),
    Cw2 = [W || W <- Cw, W /= ""],
    Cipherwords = [word:new(W, Dictionary) || W <- Cw2],
    solutions(Cipherwords, Ciphertext).

%% Prints out all solutions for Cipherwords (list of words).
%% Ciphertext is the Ciphertext we read from the file; it's just used
%% to print deciphered solutions as we go along.
%%
solutions(Cipherwords, Ciphertext) ->
    solutions(Cipherwords, Ciphertext, key:new()).

solutions(_Cipherwords = [], Ciphertext, Key) ->
    %% If there are no Cipherwords left to match, then Key is a solution.
    output(Ciphertext, Key),
    [];  % [Key].
solutions(Cipherwords, Ciphertext, Key) ->
    %% We're going to iterate over all the words in one of the
    %% Ciperwords' dictionary, so pick the one with the smallest
    %% dictionary in the hopes that we'll have less work to do.

    Cipherword = spud:min_by(
		   Cipherwords,
		   fun(Cw) -> word:dictionary_size(Cw) end),

    %% Map each word in Cipherword's dictionary to a list of solution
    %% keys, and let flatmap flatten them into one list.

    lists:flatmap(
      fun (Plainword) ->
	      %% Plainword is a tentative solution for Cipherword.  Try
	      %% to create a new key with the necessary plainletter ->
	      %% cipherletter mappings.  If there are conflicts with
	      %% existing mappings, returns 'fail'.

	      case add_to_key(Key, word:cipherword(Cipherword), Plainword) of
		  fail ->
		      %% Plainword is not a possible solution.
		      [];
		  NewKey ->
		      %% Plainword may be part of a solution.  Create a
		      %% list of NewCipherwords with Cipherword
		      %% removed, and with the remaining words'
		      %% dictionaries filtered by the new key.

		      NewCipherwords = [word:filter(W, NewKey) ||
					   W <- Cipherwords,
					   W /= Cipherword],

		      %% Return the list of solutions found by
		      %% recursively solving for the remaining cipher
		      %% words.

		      solutions(NewCipherwords, Ciphertext, NewKey)
	      end
      end,
      word:dictionary(Cipherword)).

%% Given a cipherword and it's tentative plainword, return a new key
%% based on the given key with Cipherword->Plainword letters added.
%% Return 'fail' if it's not possible to make such a key because two
%% cipher letters would need to map to the same plain letter.  Note
%% that we'll never try to map the same cipher letter to two different
%% plain letters because the dictionary filtering ensures that never
%% happens.
%%
add_to_key(Key, Cipherword, Plainword) ->
    %% Invert he key before and after we add new mappings.  This makes
    %% it easy to check whether a plaintext letter is already mapped
    %% by a different ciphertext letter.  The dictionary regexp
    %% filtering prevents a ciphertext letter from matching two
    %% different plaintext letters.
    InvertedKey = key:invert(Key),
    %% Zip into {Ciperletter, Plainletter} pairs.
    Zipped = lists:zip(Cipherword, binary:bin_to_list(Plainword)),
    %% Fold the pair mappings into key.  Return 'fail' on collisions.
    IKey2 = lists:foldl(
	      fun (_, fail) ->
		      %% The fold has already replaced the key with
		      %% 'fail'.  Just propagate it up.
		      fail;
		  ({C, P}, Accum) ->
		      %% Is there already a mapping to this plaintext letter?
		      case key:get(Accum, P) of
			  unknown ->
			      %% No.  Add P -> C to the inverted key.
			      key:set(Accum, P, C);
			  C ->
			      %% P is already mapped by C, no problem.
			      Accum;
			  _ ->
			      %% P is already mapped by a different
			      %% cipher letter.
			      fail
		      end
	      end,
	      InvertedKey,
	      Zipped),
    case IKey2 of
	fail ->
	    fail;
	_ ->
	    key:invert(IKey2)
    end.

%% Replace letters in Ciphertext with their mappings from Key.
%%
decipher(Ciphertext, Key) ->
    [key:get(Key, C) || C <- Ciphertext].

%% Print the deciphered Ciphertext to stdout.
%%
output(Ciphertext, Key) ->
    Plaintext = decipher(Ciphertext, Key),
    spud:debug("~s", [Plaintext]).
