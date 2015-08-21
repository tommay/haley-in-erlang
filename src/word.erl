-module(word).
-export([new/2, filter/2, dictionary_size/1, cipherword/1, dictionary/1]).

-record(word, {cipherword, dictionary}).

new(Cipherword, Dictionary) ->
    new(Cipherword, Dictionary, key:new()).

new(Cipherword, Dictionary, Key) ->
    Dictionary2 = filter_dictionary(Cipherword, Dictionary, Key),
    #word{cipherword = Cipherword, dictionary = Dictionary2}.

cipherword(This) ->
    This#word.cipherword.

dictionary(This) ->
    This#word.dictionary.

filter(This, Key) ->
    new(This#word.cipherword, This#word.dictionary, Key).

filter_dictionary(Cipherword, Dictionary, Key) ->
    Regexp = make_regexp(Cipherword, Key),
    [W || W <- Dictionary,
	  re:run(W, Regexp, [{capture, none}]) == match].

make_regexp(Cipherword, Key) ->
    Unknown = "[" ++ (lists:seq($a, $z) -- key:values(Key)) ++ "]",
    make_regexp(Cipherword, Key, Unknown, Cipherword, dict:new(), "").

make_regexp(_Cipherword, _Key, _Unknown, [], _Seen, Accum) ->
    {ok, R} = re:compile("^" ++ Accum ++ "$"),
    R;
make_regexp(Cipherword, Key, Unknown, [Letter | Rest], Seen, Accum) ->
    case key:get(Key, Letter, not_alpha) of
	unknown ->
	    case count(Cipherword, Letter) == 1 of
		true ->
		    make_regexp(Cipherword, Key, Unknown,
				Rest, Seen, Accum ++ Unknown);
		false ->
		    case dict:find(Letter, Seen) of
			error ->
			    N = dict:size(Seen),
			    Seen2 = dict:store(Letter, ["\\", $1 + N], Seen),
			    make_regexp(Cipherword, Key, Unknown,
					Rest, Seen2,
					Accum ++ "(" ++ Unknown ++ ")");
			{ok, Backreference} ->
			    make_regexp(Cipherword, Key, Unknown,
					Rest, Seen, Accum ++ Backreference)
		    end
	    end;
	not_alpha ->
	    make_regexp(Cipherword, Key, Unknown,
			Rest, Seen, Accum ++ [Letter]);
	Plainletter ->
	    make_regexp(Cipherword, Key, Unknown,
			Rest, Seen, Accum ++ [Plainletter])
    end.

count(List, Obj) ->
    erlang:length([E || E <- List, E == Obj]).

dictionary_size(This) ->
    erlang:length(This#word.dictionary).
