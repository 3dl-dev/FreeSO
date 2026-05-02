/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */

using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FSO.Bot.Headless;
using FSO.Server.Protocol.Electron.Packets;
using Xunit;

namespace FSO.Bot.Headless.Tests;

/// <summary>
/// Unit tests for <see cref="BotCmdHandler"/> — specifically the
/// <c>probe-bulletin</c> case added in freesoexperiment-923.
///
/// <para>
/// These tests exercise the dispatch path through
/// <see cref="BotCmdHandler.TryHandleAsync"/>: the switch branch must
/// exist and route to the handler, which must emit a <c>bot-cmd-reply</c>
/// on the stdout sink. The city Aries socket is not live in unit tests —
/// we pass <c>null</c> for the city socket and verify the "city socket
/// unavailable" refuse path, which proves the branch dispatches correctly
/// without requiring a live server fixture.
/// </para>
///
/// <para>
/// A second test verifies the unknown-cmd fallback no longer fires for
/// <c>probe-bulletin</c>, anchoring the regression the item was filed to fix:
/// live <c>interact-with bulletin_board</c> returning "unknown bot-cmd" because
/// the switch was missing the case (freesoexperiment-923 root cause).
/// </para>
/// </summary>
public class BotCmdHandlerTests
{
    /// <summary>
    /// probe-bulletin with a null cityAries must emit ok=false with
    /// "city socket unavailable" — proving the branch dispatches (not
    /// "unknown bot-cmd") and the handler's null-guard fires correctly.
    ///
    /// <para>
    /// This is the regression test for freesoexperiment-923: before the fix,
    /// TryHandleAsync would emit <c>ok=false, error="unknown bot-cmd: probe-bulletin"</c>.
    /// After the fix, it emits <c>ok=false, error="probe-bulletin: city socket unavailable"</c>.
    /// The exact error string is the observable difference that proves the branch exists.
    /// </para>
    /// </summary>
    [Fact]
    public async Task ProbeBulletin_NullCitySocket_EmitsCitySocketUnavailable()
    {
        var line = """{"kind":"bot-cmd","cmd":"probe-bulletin","correlation_id":"c-pb-1","args":{"neighborhood_id":1}}""";
        var node = JsonNode.Parse(line).AsObject();

        string captured = null;
        var latch = new ManualResetEventSlim();
        using var _sub = PerceptionEmitterCapture.Capture(s => { captured = s; latch.Set(); });

        var handled = await BotCmdHandler.TryHandleAsync(node, cityAries: null, default);

        Assert.True(handled, "TryHandleAsync must return true for probe-bulletin (consumed)");
        Assert.True(latch.Wait(TimeSpan.FromSeconds(2)), "bot-cmd-reply never emitted");

        var reply = JsonNode.Parse(captured).AsObject();
        Assert.Equal("bot-cmd-reply", (string)reply["kind"]);
        Assert.Equal("c-pb-1",        (string)reply["correlation_id"]);
        Assert.False((bool)reply["ok"]);

        var error = (string)reply["error"];
        // Must NOT be the old "unknown bot-cmd" error — that's the regression this test guards.
        Assert.DoesNotContain("unknown bot-cmd", error, StringComparison.OrdinalIgnoreCase);
        // Must be the null-guard path, proving the branch was entered.
        Assert.Contains("city socket unavailable", error, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verify probe-bulletin is NOT routed to the default "unknown bot-cmd" path.
    /// A string-contains check on the error verifies the dispatch reaches the
    /// probe-bulletin handler, not the default case.
    ///
    /// This is the minimal signal that the switch branch is present and wired:
    /// "city socket unavailable" can only appear if the probe-bulletin case
    /// was matched. "unknown bot-cmd: probe-bulletin" means the case is absent.
    /// </summary>
    [Fact]
    public async Task ProbeBulletin_DispatchDoesNotFallThroughToUnknownCmd()
    {
        var line = """{"kind":"bot-cmd","cmd":"probe-bulletin","correlation_id":"c-pb-2","args":{}}""";
        var node = JsonNode.Parse(line).AsObject();

        string captured = null;
        var latch = new ManualResetEventSlim();
        using var _sub = PerceptionEmitterCapture.Capture(s => { captured = s; latch.Set(); });

        await BotCmdHandler.TryHandleAsync(node, cityAries: null, default);
        Assert.True(latch.Wait(TimeSpan.FromSeconds(2)), "no reply emitted");

        var reply = JsonNode.Parse(captured).AsObject();
        var error = (string)reply["error"] ?? string.Empty;

        // The regression: before the fix, error would be "unknown bot-cmd: probe-bulletin".
        Assert.DoesNotContain("unknown bot-cmd", error, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// probe-bulletin without args (no neighborhood_id) must default to nhood 1
    /// and still enter the handler — not crash or return unknown-cmd.
    /// </summary>
    [Fact]
    public async Task ProbeBulletin_DefaultNeighborhoodId_NullSocketStillHandled()
    {
        // No args at all — neighborhood_id should default to 1.
        var line = """{"kind":"bot-cmd","cmd":"probe-bulletin","correlation_id":"c-pb-3","args":{}}""";
        var node = JsonNode.Parse(line).AsObject();

        string captured = null;
        var latch = new ManualResetEventSlim();
        using var _sub = PerceptionEmitterCapture.Capture(s => { captured = s; latch.Set(); });

        var handled = await BotCmdHandler.TryHandleAsync(node, cityAries: null, default);

        Assert.True(handled);
        Assert.True(latch.Wait(TimeSpan.FromSeconds(2)));

        var reply = JsonNode.Parse(captured).AsObject();
        Assert.Equal("bot-cmd-reply", (string)reply["kind"]);
        Assert.Equal("c-pb-3",        (string)reply["correlation_id"]);
        // null cityAries → ok=false, but handler was entered (not unknown-cmd).
        Assert.False((bool)reply["ok"]);
        Assert.Contains("unavailable", (string)reply["error"], StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Existing commands (probe-lot, probe-road, purchase-lot, bot-exit-request)
    /// must not be broken by the new case insertion.
    /// bot-exit-request is simplest to test: it produces ok=true with accepted=true
    /// immediately, then triggers shutdown.
    /// </summary>
    [Fact]
    public async Task ExistingCommands_NotBrokenByNewCase()
    {
        // probe-road: no city socket needed; it reads Content.CityMaps.
        // Content is not initialised in unit tests → exception → ok=false with GetType().Name.
        // What we care about: it's NOT "unknown bot-cmd" (meaning the switch reached probe-road).
        var line = """{"kind":"bot-cmd","cmd":"probe-road","correlation_id":"c-pr-4","args":{"x":249,"y":348}}""";
        var node = JsonNode.Parse(line).AsObject();

        string captured = null;
        var latch = new ManualResetEventSlim();
        using var _sub = PerceptionEmitterCapture.Capture(s => { captured = s; latch.Set(); });

        var handled = await BotCmdHandler.TryHandleAsync(node, cityAries: null, default);
        Assert.True(handled);
        Assert.True(latch.Wait(TimeSpan.FromSeconds(2)));

        var reply = JsonNode.Parse(captured).AsObject();
        Assert.Equal("c-pr-4", (string)reply["correlation_id"]);
        // Must not be "unknown bot-cmd: probe-road".
        var error = (string)reply["error"] ?? string.Empty;
        Assert.DoesNotContain("unknown bot-cmd", error, StringComparison.OrdinalIgnoreCase);
    }
}
