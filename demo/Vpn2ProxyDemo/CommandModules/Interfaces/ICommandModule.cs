using System.CommandLine;

namespace Vpn2ProxyDemo.CommandModules.Interfaces
{
    /// <summary>A self-contained subcommand: exposes the <see cref="Command"/> the root command hosts.</summary>
    internal interface ICommandModule
    {
        Command Command { get; }
    }
}
