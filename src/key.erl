-module(key).
-export([new/0, get/2, get/3, set/3, values/1, invert/1]).

-record(key, {key, inverted}).

%% A key has a tuple that maps a cipher value from $a to $z to the
%% corresponding plaintext character, or unknown if the plaintext
%% character hasn't been set yet, or just returns the cipher character
%% if it's not alphabetic.  "Inverted" maps the other way so we can be
%% sure tat each plain text is mapped by at most one cipher letter.

new() ->
    Tuple = erlang:make_tuple(26, unknown),
    #key{key = Tuple, inverted = Tuple}.

get(This, Letter) ->
    get(This, Letter, Letter).

get(This, Letter, Default) ->
    case Letter >= $a andalso Letter =< $z of
	true ->
	    erlang:element(Letter - ($a - 1), This#key.key);
	false ->
	    Default
    end.

set(This, From, To) ->
    This#key{key = set1(This#key.key, From, To),
	     inverted = set1(This#key.inverted, To, From)}.

set1(Tuple, From, To) ->
    case From >= $a andalso From =< $z of
	true ->
	    erlang:setelement(From - ($a - 1), Tuple, To);
	false ->
	    Tuple
    end.

%% Returns a list/string of all values in this Key.
%%
values(This) ->
    [V || V <- tuple_to_list(This#key.key), V /= unknown].

invert(This) ->
    This#key{key = This#key.inverted, inverted = This#key.key}.
