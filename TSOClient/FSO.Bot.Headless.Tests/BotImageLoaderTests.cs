/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */

using System;
using System.IO;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FSO.Bot.Headless;
using FSO.Content.Model;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Bmp;
using SixLabors.ImageSharp.PixelFormats;
using Xunit;

namespace FSO.Bot.Headless.Tests;

/// <summary>
/// Unit + integration coverage for <see cref="BotImageLoader"/> (automataisland-c3b).
///
/// <para>
/// The unit tests do not require game assets: they synthesise BMP/PNG streams in-memory
/// via ImageSharp itself. The integration test (gated on <c>FSO_INTEGRATION=1</c>) drives
/// the full probe-road path with a real Content.Init and asserts the road-bits reply that
/// pre-fix returned a NullReferenceException.
/// </para>
/// </summary>
public class BotImageLoaderTests
{
    /// <summary>
    /// After <see cref="BotImageLoader.WireImageFetch"/>, the static
    /// <see cref="AbstractTextureRef.ImageFetchFunction"/> hook must be non-null.
    /// Pre-fix the bot left it null because Content.Init(device:null) never assigns it
    /// (Content.cs:106-125).
    /// </summary>
    [Fact]
    public void WireImageFetch_SetsImageFetchFunction()
    {
        // Reset to null to make the assertion meaningful even if another test wired it.
        AbstractTextureRef.ImageFetchFunction = null;

        BotImageLoader.WireImageFetch();

        Assert.NotNull(AbstractTextureRef.ImageFetchFunction);
    }

    /// <summary>
    /// WireImageFetch must not clobber an already-wired function. A second caller
    /// (e.g. an embedded test harness) that wires its own fetcher first should win.
    /// </summary>
    [Fact]
    public void WireImageFetch_DoesNotOverwriteExisting()
    {
        // Mint a sentinel that returns a recognisable TexBitmap; we identify it by
        // the PixelSize rather than delegate identity (delegate equality on a method-group
        // assignment creates a fresh delegate each time, so reference compare fails).
        AbstractTextureRef.SimpleBitmapProvider sentinel =
            (s, r) => new TexBitmap { PixelSize = 99 };
        AbstractTextureRef.ImageFetchFunction = sentinel;

        BotImageLoader.WireImageFetch();

        var observed = AbstractTextureRef.ImageFetchFunction(Stream.Null, null);
        Assert.Equal(99, observed.PixelSize);

        // Cleanup so we don't leak the sentinel into other tests.
        AbstractTextureRef.ImageFetchFunction = null;
    }

    /// <summary>
    /// SoftImageFetch must decode a real BMP stream into a 4-byte-per-pixel TexBitmap
    /// with the right dimensions. This is the function that pre-fix the bot didn't have:
    /// CityMap roadmap loading relies on it returning non-null with .Data populated.
    /// </summary>
    [Fact]
    public void SoftImageFetch_DecodesBmp_ReturnsPopulatedTexBitmap()
    {
        var bmp = BuildBmpStream(width: 8, height: 4);
        var tex = BotImageLoader.SoftImageFetch(bmp, texRef: null);

        Assert.NotNull(tex);
        Assert.Equal(8, tex.Width);
        Assert.Equal(4, tex.Height);
        Assert.Equal(4, tex.PixelSize);
        Assert.NotNull(tex.Data);
        Assert.Equal(8 * 4 * 4, tex.Data.Length);
    }

    /// <summary>
    /// A corrupt / unreadable stream returns an empty-Data TexBitmap (not a throw, not null).
    /// Matches CoreImageLoader's contract — TextureValueMap iterates Data.Length which is 0,
    /// so the resulting map stays default-valued without crashing the load.
    /// </summary>
    [Fact]
    public void SoftImageFetch_CorruptStream_ReturnsEmptyTexBitmap()
    {
        var corrupt = new MemoryStream(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        var tex = BotImageLoader.SoftImageFetch(corrupt, texRef: null);

        Assert.NotNull(tex);
        Assert.NotNull(tex.Data);
        Assert.Empty(tex.Data);
    }

    // ---- integration: real probe-road on real content ----

    private static readonly bool IntegrationEnabled =
        Environment.GetEnvironmentVariable("FSO_INTEGRATION") == "1";

    private static string GameLocation
    {
        get
        {
            var loc = Environment.GetEnvironmentVariable("FSO_GAME_LOCATION")
                      ?? "/home/baron/projects/freeso-experiment/GameAssets/TSOClient/";
            if (!loc.EndsWith(Path.DirectorySeparatorChar)
                && !loc.EndsWith(Path.AltDirectorySeparatorChar))
                loc += Path.DirectorySeparatorChar;
            return loc;
        }
    }

    /// <summary>
    /// Live regression test for automataisland-c3b. Initialises Content the way the bot does,
    /// wires the image fetcher, then drives probe-road through BotCmdHandler at the same
    /// (x, y) Mara hit (249, 348). Pre-fix this returned
    /// "probe-road: NullReferenceException". Post-fix it returns ok=true with road_bits.
    ///
    /// <para>
    /// Gated on <c>FSO_INTEGRATION=1</c> because Content.Init needs the TSO asset tree.
    /// </para>
    /// </summary>
    [Xunit.SkippableFact]
    public async Task ProbeRoad_OnRealContent_ReturnsOkAndRoadBits()
    {
        Xunit.Skip.IfNot(IntegrationEnabled,
            "set FSO_INTEGRATION=1 (and ensure GameAssets/TSOClient/cities/city_0001/roadmap.bmp exists) to run this test");

        FSO.SimAntics.VMContext.InitVMConfig(false);
        FSO.Content.Content.Init(GameLocation, FSO.Content.ContentMode.SERVER);
        BotImageLoader.WireImageFetch();

        var handler = new BotCmdHandler();
        var line = """{"kind":"bot-cmd","cmd":"probe-road","correlation_id":"c-c3b-1","args":{"x":249,"y":348}}""";
        var node = JsonNode.Parse(line).AsObject();

        string captured = null;
        var latch = new ManualResetEventSlim();
        using var _sub = PerceptionEmitterCapture.Capture(s => { captured = s; latch.Set(); });

        var handled = await handler.TryHandleAsync(node, cityAries: null, default);
        Assert.True(handled);
        Assert.True(latch.Wait(TimeSpan.FromSeconds(5)));

        var reply = JsonNode.Parse(captured).AsObject();
        Assert.Equal("c-c3b-1", (string)reply["correlation_id"]);
        Assert.True((bool)reply["ok"],
            $"probe-road should succeed once ImageFetchFunction is wired; got error={(string)reply["error"]}");

        // Payload nests under "data" per EmitReply contract.
        var data = reply["data"].AsObject();
        Assert.NotNull(data["road_bits"]);
        Assert.NotNull(data["has_road"]);
        Assert.Equal(249, (int)data["x"]);
        Assert.Equal(348, (int)data["y"]);
    }

    // ---- helpers ----

    private static MemoryStream BuildBmpStream(int width, int height)
    {
        using var image = new Image<Rgba32>(width, height);
        for (int y = 0; y < height; y++)
            for (int x = 0; x < width; x++)
                image[x, y] = new Rgba32((byte)(x * 32), (byte)(y * 64), 128, 255);

        var ms = new MemoryStream();
        image.Save(ms, new BmpEncoder());
        ms.Position = 0;
        return ms;
    }
}
