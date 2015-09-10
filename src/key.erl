-module(key).
-export([new/0, get/2, get/3, set/3, values/1, invert/1]).

-record(key, {key, inverted}).

%% A key maps cipher letters to plain letters, or to 'unknown' for
%% cipher letters that haven't been set yet.  It has two tuples, "key"
%% and "inverted", that are used as arrays indexed by cipher letters
%% from $a to $z that map to the corresponding plaintext letter, or to
%% 'unknown'.  "Inverted" maps the other way, so we can quickly invert
%% the key to ensure that each plain letter is mapped by at most one
%% cipher letter.

%% Creates a new key, with all mappings set to 'unknown'.
%%
new() ->
    Tuple = erlang:make_tuple(26, unknown),
    #key{key = Tuple, inverted = Tuple}.

%% Returns the mapped letter for Letter.  If Letter is not alphabetic,
%% returns Letter itself.  This allows punctuation, etc., to "map" to
%% itself.
%%
get(This, Letter) ->
    get(This, Letter, Letter).

%% Returns the mapping for Letter, or 'unknown'.  If Letter is not
%% alphabetic, returns returns Default.
%%
get(This, Letter, Default) ->
    case Letter >= $a andalso Letter =< $z of
	true ->
	    erlang:element(Letter - ($a - 1), This#key.key);
	false ->
	    Default
    end.

%% Returns a new key with "From" mapped to "To".
%%
set(This, From, To) ->
    % Set both forwards and reverse mappings.
    This#key{key = set1(This#key.key, From, To),
	     inverted = set1(This#key.inverted, To, From)}.

set1(Tuple, From, To) ->
    % XXX do we need this check?
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

%% Returns a key with the mapping inverted.
%%
invert(This) ->
    % Since we already maintain the inverted mapping, just swap the
    % mappings.
    This#key{key = This#key.inverted, inverted = This#key.key}.
