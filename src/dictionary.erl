-module(dictionary).
-export([new/1, plainwords/3]).
-compile(export_all).

-record(dictionary, {words}).

new(Filename) ->
    #dictionary{words = load_words(Filename)}.

load_words(Filename) ->
    {ok, Raw} = file:read_file(Filename),
    re:split(Raw, "\\n", [{return, list}]).

plainwords(This, Cipherword, Key) ->
    Regexp = make_regexp(Cipherword, Key),
    lists:flatmap(
      fun(W) ->
	      case re:run(W, Regexp, [{capture, none}]) of
		  match ->
		      [W];
		  _ ->
		      []
	      end
      end,
      This#dictionary.words).

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

%%count(List, Obj) ->
%%    lists:foldl(
%%      fun(E, Count) ->
%%	      case E == Obj of
%%		  true -> Count + 1;
%%		  false -> Count
%%	      end
%%      end,
%%      0,
%%      List).
