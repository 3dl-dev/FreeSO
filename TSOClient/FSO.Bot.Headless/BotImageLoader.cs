/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */

using System.IO;
using FSO.Content.Model;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace FSO.Bot.Headless;

/// <summary>
/// CPU-only image loader for the headless bot.
///
/// <para>
/// <c>FSO.Content.Content.Init</c> only wires <c>AbstractTextureRef.ImageFetchFunction</c>
/// when constructed with a non-null <c>GraphicsDevice</c> (Content.cs:106-125). The headless
/// bot has no GraphicsDevice, so without this loader <c>ImageFetchFunction</c> stays null —
/// any later <c>texture.GetImage()</c> call returns null (TextureRef.cs:208), and the next
/// access on the result NREs.
/// </para>
///
/// <para>
/// First observed via <c>probe-road</c> (automataisland-c3b): lazy CityMap construction in
/// CityMapsProvider.Get loads roadmap.bmp through TextureValueMap, which NREs on the null
/// TexBitmap. Same root cause would surface in any other code path that reads pixel data
/// from a FileTextureRef in the bot process.
/// </para>
///
/// <para>
/// FSO.Server.Core/Program.cs and FSO.Server/ToolRunServer.cs already solve this for the
/// server's headless modes by wiring <see cref="SoftImageFetch"/>; we mirror that here
/// rather than reference FSO.Server.Core (which drags FSO.Server in transitively).
/// </para>
/// </summary>
public static class BotImageLoader
{
    /// <summary>
    /// Wire <see cref="AbstractTextureRef.ImageFetchFunction"/> to a CPU-only loader.
    /// Idempotent: re-running has no effect once set. Call after <c>Content.Init</c> and
    /// before any code that lazy-loads CityMap / world textures.
    /// </summary>
    public static void WireImageFetch()
    {
        if (AbstractTextureRef.ImageFetchFunction == null)
        {
            AbstractTextureRef.ImageFetchFunction = SoftImageFetch;
        }
    }

    /// <summary>
    /// Decode an image stream into a BGRA <see cref="TexBitmap"/> without a GraphicsDevice.
    /// Mirrors FSO.Server.Core.CoreImageLoader.SoftImageFetch.
    /// </summary>
    public static TexBitmap SoftImageFetch(Stream stream, AbstractTextureRef texRef)
    {
        Image<Rgba32> result;
        try
        {
            result = Image.Load<Rgba32>(stream);
        }
        catch
        {
            return new TexBitmap { Data = new byte[0] };
        }
        stream.Close();

        if (result == null) return null;

        var data = new byte[result.Width * result.Height * 4];
        result.CopyPixelDataTo(data);

        // RGBA → BGRA (matches ImageFetchWithDevice output convention)
        for (int i = 0; i < data.Length; i += 4)
        {
            var temp = data[i];
            data[i] = data[i + 2];
            data[i + 2] = temp;
        }

        return new TexBitmap
        {
            Data = data,
            Width = result.Width,
            Height = result.Height,
            PixelSize = 4,
        };
    }
}
