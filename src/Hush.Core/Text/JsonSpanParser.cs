using System.Globalization;
using System.Text;

namespace Hush.Core.Text;

/// <summary>A JSON value with its exact position in the source text, so edits can be surgical.</summary>
public abstract record JsonNode(int Start, int End)
{
    /// <summary>The source text of this node.</summary>
    public string Raw(string source)
    {
        ArgumentNullException.ThrowIfNull(source);
        return source[Start..End];
    }
}

/// <summary>An object: <c>{ ... }</c>. <see cref="JsonNode.Start"/> is the brace, <see cref="JsonNode.End"/> is after the closing brace.</summary>
public sealed record JsonObjectNode(int Start, int End, IReadOnlyList<JsonMember> Members) : JsonNode(Start, End)
{
    /// <summary>The first member named <paramref name="name"/>, or null.</summary>
    public JsonMember? Get(string name) => Members.FirstOrDefault(m => m.Name == name);

    /// <summary>The value of member <paramref name="name"/> if it is an object.</summary>
    public JsonObjectNode? GetObject(string name) => Get(name)?.Value as JsonObjectNode;
}

/// <summary>An object member. <see cref="Start"/> is the key's opening quote; <see cref="End"/> is the end of the value.</summary>
public sealed record JsonMember(int Start, int End, string Name, JsonNode Value);

/// <summary>An array.</summary>
public sealed record JsonArrayNode(int Start, int End, IReadOnlyList<JsonNode> Items) : JsonNode(Start, End);

/// <summary>A string (decoded value; the raw text keeps the original escapes).</summary>
public sealed record JsonStringNode(int Start, int End, string Value) : JsonNode(Start, End);

/// <summary>A number, boolean or null.</summary>
public sealed record JsonLiteralNode(int Start, int End, string Text) : JsonNode(Start, End);

/// <summary>
/// A small JSON parser that records spans and accepts the JSONC extensions VS Code uses (comments and
/// trailing commas). It exists so the migrator can change a few values while leaving every other byte of a
/// user's config exactly as it was.
/// </summary>
public sealed class JsonSpanParser
{
    private readonly string _text;
    private int _position;

    private JsonSpanParser(string text) => _text = text;

    /// <summary>Parses <paramref name="text"/>. Throws <see cref="FormatException"/> with a line number on error.</summary>
    public static JsonNode Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var parser = new JsonSpanParser(text);
        parser.SkipTrivia();
        if (parser._position < text.Length && text[parser._position] == '﻿')
        {
            parser._position++;
            parser.SkipTrivia();
        }

        var node = parser.ParseValue();
        parser.SkipTrivia();
        if (parser._position != text.Length)
        {
            throw parser.Error("Unexpected content after the JSON value");
        }

        return node;
    }

    /// <summary>Encodes a string as a JSON string literal.</summary>
    public static string Quote(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var builder = new StringBuilder(value.Length + 2).Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                case '\b': builder.Append("\\b"); break;
                case '\f': builder.Append("\\f"); break;
                default:
                    if (c < 0x20)
                    {
                        builder.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(c);
                    }

                    break;
            }
        }

        return builder.Append('"').ToString();
    }

    private JsonNode ParseValue()
    {
        if (_position >= _text.Length)
        {
            throw Error("Unexpected end of input");
        }

        return _text[_position] switch
        {
            '{' => ParseObject(),
            '[' => ParseArray(),
            '"' => ParseString(),
            _ => ParseLiteral(),
        };
    }

    private JsonObjectNode ParseObject()
    {
        var start = _position++;
        var members = new List<JsonMember>();
        while (true)
        {
            SkipTrivia();
            if (Peek() == '}')
            {
                _position++;
                return new JsonObjectNode(start, _position, members);
            }

            if (Peek() != '"')
            {
                throw Error("Expected a property name");
            }

            var key = ParseString();
            SkipTrivia();
            if (Peek() != ':')
            {
                throw Error("Expected ':'");
            }

            _position++;
            SkipTrivia();
            var value = ParseValue();
            members.Add(new JsonMember(key.Start, value.End, key.Value, value));
            SkipTrivia();
            if (Peek() == ',')
            {
                _position++;
                continue;
            }

            if (Peek() == '}')
            {
                _position++;
                return new JsonObjectNode(start, _position, members);
            }

            throw Error("Expected ',' or '}'");
        }
    }

    private JsonArrayNode ParseArray()
    {
        var start = _position++;
        var items = new List<JsonNode>();
        while (true)
        {
            SkipTrivia();
            if (Peek() == ']')
            {
                _position++;
                return new JsonArrayNode(start, _position, items);
            }

            items.Add(ParseValue());
            SkipTrivia();
            if (Peek() == ',')
            {
                _position++;
                continue;
            }

            if (Peek() == ']')
            {
                _position++;
                return new JsonArrayNode(start, _position, items);
            }

            throw Error("Expected ',' or ']'");
        }
    }

    private JsonStringNode ParseString()
    {
        var start = _position++;
        var builder = new StringBuilder();
        while (true)
        {
            if (_position >= _text.Length)
            {
                throw Error("Unterminated string");
            }

            var c = _text[_position++];
            if (c == '"')
            {
                return new JsonStringNode(start, _position, builder.ToString());
            }

            if (c != '\\')
            {
                builder.Append(c);
                continue;
            }

            if (_position >= _text.Length)
            {
                throw Error("Unterminated escape");
            }

            var e = _text[_position++];
            switch (e)
            {
                case '"': builder.Append('"'); break;
                case '\\': builder.Append('\\'); break;
                case '/': builder.Append('/'); break;
                case 'b': builder.Append('\b'); break;
                case 'f': builder.Append('\f'); break;
                case 'n': builder.Append('\n'); break;
                case 'r': builder.Append('\r'); break;
                case 't': builder.Append('\t'); break;
                case 'u':
                    if (_position + 4 > _text.Length || !int.TryParse(_text.AsSpan(_position, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code))
                    {
                        throw Error("Invalid \\u escape");
                    }

                    builder.Append((char)code);
                    _position += 4;
                    break;
                default:
                    throw Error($"Invalid escape '\\{e}'");
            }
        }
    }

    private JsonLiteralNode ParseLiteral()
    {
        var start = _position;
        while (_position < _text.Length && (char.IsAsciiLetterOrDigit(_text[_position]) || _text[_position] is '-' or '+' or '.'))
        {
            _position++;
        }

        if (_position == start)
        {
            throw Error($"Unexpected character '{_text[start]}'");
        }

        var text = _text[start.._position];
        if (text is not ("true" or "false" or "null") && !double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out _))
        {
            throw Error($"Invalid literal '{text}'");
        }

        return new JsonLiteralNode(start, _position, text);
    }

    private void SkipTrivia()
    {
        while (_position < _text.Length)
        {
            var c = _text[_position];
            if (char.IsWhiteSpace(c))
            {
                _position++;
            }
            else if (c == '/' && _position + 1 < _text.Length && _text[_position + 1] == '/')
            {
                while (_position < _text.Length && _text[_position] != '\n')
                {
                    _position++;
                }
            }
            else if (c == '/' && _position + 1 < _text.Length && _text[_position + 1] == '*')
            {
                var close = _text.IndexOf("*/", _position + 2, StringComparison.Ordinal);
                if (close < 0)
                {
                    throw Error("Unterminated comment");
                }

                _position = close + 2;
            }
            else
            {
                return;
            }
        }
    }

    private char Peek() => _position < _text.Length ? _text[_position] : '\0';

    private FormatException Error(string message)
    {
        var line = 1;
        for (var i = 0; i < Math.Min(_position, _text.Length); i++)
        {
            if (_text[i] == '\n')
            {
                line++;
            }
        }

        return new FormatException($"{message} at line {line}.");
    }
}
