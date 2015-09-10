-module(word).
-export([new/2, filter/2, dictionary_size/1, cipherword/1, dictionary/1]).

-record(word, {cipherword, dictionary}).

%% A word has a cipherword which is a string from the ciphertext, and
%% a dictionary which is just a list of plaintext binaries the
%% cipherword might match, given some (possibly empty) key.  As we
%% tentatively match each cipherword, the key is extended and a new
%% word is constructed for each cipherword with a reduced dictionary.

%% Creates a new word for Cipherword with a dictionary containing all
%% plaintext strings from Dictionary that could match the ciphertext.
%%
new(Cipherword, Dictionary) ->
    new(Cipherword, Dictionary, key:new()).

%% Creates a new word for Cipherword with a dictionary containing all
%% plaintext strings from Dictionary that could match the ciphertext
%% with the given Key.
%%
new(Cipherword, Dictionary, Key) ->
    Dictionary2 = filter_dictionary(Cipherword, Dictionary, Key),
    #word{cipherword = Cipherword, dictionary = Dictionary2}.

cipherword(This) ->
    This#word.cipherword.

dictionary(This) ->
    This#word.dictionary.

%% Creates a new word based on this word, but with the dictionary
%% filtered to strings that are compatible with Key.
%%
filter(This, Key) ->
    new(This#word.cipherword, This#word.dictionary, Key).

%% Returns a new Dictionary (which is just a list of strings)
%% containing all the strings of the given Dictionary which are
%% compatible with the given Cipherword string and Key.
%%
filter_dictionary(Cipherword, Dictionary, Key) ->
    Regexp = make_regexp(Cipherword, Key),
    [W || W <- Dictionary,
	  re:run(W, Regexp, [{capture, none}]) == match].

%% Returns a regular expression that will match all plainwords that
%% are compatible with the given Cipherword and Key, except that
%% multiple cipher letters which are not in Key may match the same
%% plain letter.  Those matches need to be tested and rejected later.
%%
%% Some examples when Key is empty:
%% x -> ^[a-z]$
%% xy -> ^[a-z][a-z]$
%%   Note that this could math "oo" which is not actually valid
%%   because the two letters must be different.  This is handled
%%   later when extending the Key and it's discovered that "x"
%%   and "y" must both map to "o" and the match is rejected.
%% xyx -> ^([a-z])[a-z]\1$
%%   Backreferences are used where necessary to ensure that a cipher
%%   letter appearing multiple times in the cipherword will match the
%%   same plain letter every time.
%% x'y -> ^[a-z]'[a-z]$
%%   Non-alpha characterz match themselves.  This handles words with
%%   apostrophes.
%%
%% Cipher letters that are in Key match their corresponding plain
%% letter.  E.g., when Key is {x => b}, then xyx -> ^b[a-z]b$.
%%
%% The regexp used for cipher letters that are not yet in the key
%% isn't actually [a-z] as shown in these examples, it's a character
%% class contining all the plain letters that aren't yet in the key.
%%
make_regexp(Cipherword, Key) ->
    % Unknown is a regexp that matches any plain letter that's not yet
    % in the key.  Unknown cipher letters can match any of these
    % plain letters.
    Unknown = "[" ++ (lists:seq($a, $z) -- key:values(Key)) ++ "]",
    make_regexp(Cipherword, Key, Unknown, Cipherword, dict:new(), "").

%% Generates the regexp by recursing through a cipherword and using
%% some additional values to maintain state.  Cipherword, Key, and
%% Unknown are contant.  _Cw is the list we recurse through, Backrefs
%% is a dict that keeps track of the unknown cipher letters we've seen
%% so we can create backreferences (it's actually a map of cipher
%% letters to backreference strings), and Accum is where we accumulate
%% the regular expression by appending.
%%
make_regexp(_Cipherword, _Key, _Unknown, _Cw = [], _Backrefs, Accum) ->
    {ok, R} = re:compile("^" ++ Accum ++ "$"),
    R;
make_regexp(Cipherword, Key, Unknown, _Cw = [Letter | Rest], Backrefs, Accum) ->
    case key:get(Key, Letter, not_alpha) of
	unknown ->
	    %% Letter does not yet have a mapping.  It will match the
	    %% set of Unknown letters.  But if the letter appears in
	    %% Cipherword more than once then use a capture group or,
	    %% if we've already created a capture group for this
	    %% letter, use its backreference.
	    case count(Cipherword, Letter) == 1 of
		true ->
		    %% Letter occurs once, it just matches Unknown.
		    make_regexp(Cipherword, Key, Unknown,
				Rest, Backrefs, Accum ++ Unknown);
		false ->
		    %% If we've already made a backreference for this
		    %% letter then use it.  Otherwise make it and add
		    %% it to Backrefs.
		    case dict:find(Letter, Backrefs) of
			{ok, Backref} ->
			    make_regexp(Cipherword, Key, Unknown,
					Rest, Backrefs, Accum ++ Backref);
			error ->
			    N = dict:size(Backrefs),
			    Backrefs2 = dict:store(
					  Letter, ["\\", $1 + N], Backrefs),
			    make_regexp(Cipherword, Key, Unknown,
					Rest, Backrefs2,
					Accum ++ "(" ++ Unknown ++ ")")
		    end
	    end;
	not_alpha ->
	    %% Non-alphanetic characters match themselves.
	    make_regexp(Cipherword, Key, Unknown,
			Rest, Backrefs, Accum ++ [Letter]);
	Plainletter ->
	    %% Letter maps to Plainletter.  Match Plainletter.
	    make_regexp(Cipherword, Key, Unknown,
			Rest, Backrefs, Accum ++ [Plainletter])
    end.

%% Returns the number of times Obj occurs in List.
%%
count(List, Obj) ->
    erlang:length([E || E <- List, E == Obj]).

%% Returns the size of the word's dictionary.
%%
dictionary_size(This) ->
    erlang:length(This#word.dictionary).
