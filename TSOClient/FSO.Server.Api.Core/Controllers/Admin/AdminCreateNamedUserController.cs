using FSO.Server.Api.Core.Utils;
using FSO.Server.Common;
using FSO.Server.Database.DA;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Dapper;

namespace FSO.Server.Api.Core.Controllers.Admin
{
    /// <summary>
    /// Admin endpoint for provisioning canonical named talent accounts on grid_31337
    /// (Mara, Lara, Reeve, Marin, build-crew members — anything that needs a stable
    /// human-readable username, not an auto-numbered <c>bot&lt;n&gt;</c>).
    ///
    /// <para>
    /// POST /admin/create-named-user
    /// Header: <c>Authorization: Bearer &lt;FSO_ADMIN_TOKEN&gt;</c>
    /// Body:   <c>{ "username": "...", "password": "...", "email": "..." (optional) }</c>
    /// Returns 200: <c>{ "username": "...", "user_id": N, "created": true }</c>
    /// Returns 200: <c>{ "username": "...", "user_id": N, "created": false }</c> on
    /// idempotent re-call when the username already exists (we do NOT touch the
    /// existing row — re-running this endpoint never overwrites an existing
    /// password).
    /// </para>
    ///
    /// <para>
    /// Pre-fix, every named-talent provisioning on grid_31337 (Mara, Lara, Reeve)
    /// required direct INSERT into <c>fso_users</c> + <c>fso_user_authenticate</c>
    /// with a Python PBKDF2 shim. This endpoint replaces that workaround so the
    /// arrival pipeline (Welcome Center + future <c>/persona-hire</c>) can provision
    /// accounts over the admin API like everything else.
    /// </para>
    ///
    /// <para>
    /// Mirrors <see cref="AdminAllocateBotController"/> on auth posture, locking, and
    /// password hashing. Differs in that the username comes from the request (not
    /// auto-allocated) and the password is caller-chosen (not random).
    /// </para>
    /// </summary>
    [Route("admin/create-named-user")]
    [ApiController]
    public class AdminCreateNamedUserController : ControllerBase
    {
        // Match the FSO server's UserController validation (digits + lowercase letters,
        // 3-24 chars) so accounts created here can authenticate the same way real
        // user-driven registrations do.
        private static readonly Regex USERNAME_REGEX =
            new Regex("^[a-z0-9]{3,24}$", RegexOptions.Compiled);

        // PasswordHasher.Hash uses Rfc2898 with 1000 iterations; min length kept loose
        // to allow the canonical talent passwords (e.g. "test1234") to round-trip.
        private const int PASSWORD_MIN_LEN = 8;
        private const int PASSWORD_MAX_LEN = 128;

        public class CreateNamedUserRequest
        {
            public string username { get; set; }
            public string password { get; set; }
            public string email { get; set; }
        }

        [HttpPost]
        public async Task<IActionResult> CreateNamedUser([FromBody] CreateNamedUserRequest body)
        {
            // ---- Auth (BEFORE any DB I/O) ----
            var auth = Request.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(auth) || !auth.StartsWith("Bearer ", StringComparison.Ordinal))
            {
                return Unauthorized();
            }
            var presented = auth.Substring("Bearer ".Length);
            var expected = Environment.GetEnvironmentVariable("FSO_ADMIN_TOKEN");
            if (string.IsNullOrEmpty(expected) || string.IsNullOrEmpty(presented))
            {
                return Unauthorized();
            }
            var presentedBytes = Encoding.UTF8.GetBytes(presented);
            var expectedBytes = Encoding.UTF8.GetBytes(expected);
            if (presentedBytes.Length != expectedBytes.Length ||
                !CryptographicOperations.FixedTimeEquals(presentedBytes, expectedBytes))
            {
                return Unauthorized();
            }

            // ---- Validate body ----
            if (body == null)
            {
                return BadRequest(new { error = "body required (JSON: {username, password, email?})" });
            }
            var username = body.username?.Trim();
            var password = body.password;
            if (string.IsNullOrEmpty(username) || !USERNAME_REGEX.IsMatch(username))
            {
                return BadRequest(new
                {
                    error = "username must match ^[a-z0-9]{3,24}$"
                });
            }
            if (string.IsNullOrEmpty(password)
                || password.Length < PASSWORD_MIN_LEN
                || password.Length > PASSWORD_MAX_LEN)
            {
                return BadRequest(new
                {
                    error = $"password length must be in [{PASSWORD_MIN_LEN}, {PASSWORD_MAX_LEN}]"
                });
            }
            var email = string.IsNullOrWhiteSpace(body.email)
                ? username + "@grid31337.localhost"
                : body.email.Trim();

            // ---- Atomic provision (idempotent) ----
            await Task.CompletedTask; // keep ApiController convention; no awaits in body.
            var api = Api.INSTANCE;
            using (var da = api.DAFactory.Get())
            {
                var sqlDa = (SqlDA)da;
                var conn = sqlDa.Context.Connection;
                if (conn.State != System.Data.ConnectionState.Open)
                {
                    conn.Open();
                }
                using (var tx = conn.BeginTransaction())
                {
                    try
                    {
                        // SELECT ... FOR UPDATE on the row (if any) prevents a parallel
                        // call from inserting the same username between our existence
                        // check and our INSERT.
                        var existingId = conn.QueryFirstOrDefault<uint?>(
                            "SELECT user_id FROM fso_users WHERE username = @username FOR UPDATE",
                            new { username },
                            transaction: tx);

                        if (existingId.HasValue && existingId.Value != 0)
                        {
                            tx.Commit();
                            return ApiResponse.Json(HttpStatusCode.OK, new
                            {
                                username,
                                user_id = existingId.Value,
                                created = false,
                            });
                        }

                        var passhash = PasswordHasher.Hash(password);
                        var now = Epoch.Now;
                        var ip = ApiUtils.GetIP(Request) ?? "127.0.0.1";

                        var userId = conn.Query<uint>(
                            "INSERT INTO fso_users " +
                            "(username, email, user_state, register_date, is_admin, is_moderator, is_banned, register_ip, last_ip) " +
                            "VALUES (@username, @email, 'valid', @register_date, 0, 0, 0, @ip, @ip); " +
                            "SELECT LAST_INSERT_ID();",
                            new
                            {
                                username,
                                email,
                                register_date = now,
                                ip,
                            },
                            transaction: tx).First();

                        conn.Execute(
                            "INSERT INTO fso_user_authenticate (user_id, scheme_class, data) " +
                            "VALUES (@user_id, @scheme_class, @data);",
                            new
                            {
                                user_id = userId,
                                scheme_class = passhash.scheme,
                                data = passhash.data,
                            },
                            transaction: tx);

                        tx.Commit();

                        return ApiResponse.Json(HttpStatusCode.OK, new
                        {
                            username,
                            user_id = userId,
                            created = true,
                        });
                    }
                    catch
                    {
                        try { tx.Rollback(); } catch { }
                        throw;
                    }
                }
            }
        }
    }
}
