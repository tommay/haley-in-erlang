-module(key).
-export([new/0, get/2, get/3, set/3, values/1]).

%% A key is a tuple that maps an cipher value from $a to $z to the
%% corresponding plaintext charactere, or unknown if the plaintext
%% character hasn't been set yet, or just returns the cipher character
%% if it's not alphabetic.

new() ->
    erlang:make_tuple(26, unknown).

get(This, Letter) ->
    get(This, Letter, Letter).

get(This, Letter, Default) ->
    case Letter >= $a andalso Letter =< $z of
	true ->
	    erlang:element(Letter - ($a - 1), This);
	false ->
	    Default
    end.

set(This, From, To) ->
    case From >= $a andalso From =< $z of
	true ->
	    erlang:setelement(From - ($a - 1), This, To);
	false ->
	    This
    end.

%% Returns a list/string of all values in this Key.
%%
values(This) ->
    values(This, 1, []).

values(This, N, Accum) ->
    case N =< erlang:size(This) of
	true ->
	    case erlang:element(N, This) of
		unknown ->
		    values(This, N + 1, Accum);
		Letter ->
		    values(This, N + 1, [Letter | Accum])
	    end;
	false ->
	    Accum
    end.
