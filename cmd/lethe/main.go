package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Operative-001/lethe/internal/crypto"
	"github.com/Operative-001/lethe/internal/directory"
	"github.com/Operative-001/lethe/internal/node"
	"github.com/Operative-001/lethe/internal/proxy"
	"github.com/Operative-001/lethe/internal/transport"
	"github.com/spf13/cobra"
)

func defaultDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lethe")
}

var rootCmd = &cobra.Command{
	Use:   "lethe",
	Short: "The network that forgets.",
	Long: `Lethe — anonymous peer-to-peer communication.

No server. No phone number. No metadata. No trace.

Every node sends exactly the same amount of traffic at all times.
Real messages are indistinguishable from cover traffic.
No node knows who is talking to whom — not even the relays.`,
}

// ─── keygen ─────────────────────────────────────────────────────────────────

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		dataDir, _ := cmd.Flags().GetString("data")
		path := filepath.Join(dataDir, "identity.json")

		if _, err := os.Stat(path); err == nil {
			fmt.Printf("Identity already exists at %s\n", path)
			fmt.Print("Overwrite? [y/N] ")
			var resp string
			fmt.Scanln(&resp)
			if !strings.EqualFold(strings.TrimSpace(resp), "y") {
				fmt.Println("Aborted.")
				return nil
			}
		}

		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			return err
		}
		if err := kp.Save(path); err != nil {
			return err
		}
		fmt.Printf("\n✓ Identity generated\n")
		fmt.Printf("  Public key : %s\n", kp.PublicKeyHex())
		fmt.Printf("  Saved to   : %s\n\n", path)
		fmt.Println("Share your public key with others so they can message you.")
		fmt.Println("Run 'lethe register <name>' after starting the daemon to register a name.")
		return nil
	},
}

// ─── daemon ──────────────────────────────────────────────────────────────────

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start the Lethe node (this is all you need)",
	RunE: func(cmd *cobra.Command, args []string) error {
		dataDir, _ := cmd.Flags().GetString("data")
		listen, _ := cmd.Flags().GetString("listen")
		proxyAddr, _ := cmd.Flags().GetString("proxy")
		bootstrapList, _ := cmd.Flags().GetStringSlice("bootstrap")

		identityPath := filepath.Join(dataDir, "identity.json")
		kp, err := crypto.LoadKeyPair(identityPath)
		if err != nil {
			return fmt.Errorf("no identity found at %s — run 'lethe keygen' first", identityPath)
		}

		if err := os.MkdirAll(dataDir, 0700); err != nil {
			return err
		}

		dir, err := directory.New(dataDir)
		if err != nil {
			return fmt.Errorf("open directory: %w", err)
		}
		defer dir.Close()

		tr := transport.NewTCP(listen)
		exposePort, _ := cmd.Flags().GetInt("expose")

		n, err := node.New(node.Config{
			Keys:       kp,
			Transport:  tr,
			Directory:  dir,
			Bootstrap:  bootstrapList,
			Rate:       100 * time.Millisecond,
			ExposePort: exposePort,
		})
		if err != nil {
			return err
		}
		if err := n.Start(); err != nil {
			return err
		}
		defer n.Stop()

		// Start SOCKS5 proxy
		proxySrv := proxy.New(proxyAddr, n, false)
		go func() {
			if err := proxySrv.ListenAndServe(); err != nil {
				log.Printf("proxy: %v", err)
			}
		}()

		// Print incoming messages to stdout
		go func() {
			for msg := range n.Messages() {
				from := msg.From
				if entry := dir.LookupByKey(from); entry != nil {
					from = entry.Name + " (" + from[:8] + "...)"
				} else if len(from) > 16 {
					from = from[:16] + "..."
				}
				fmt.Printf("\n📨 [%s] %s\n> ", from, msg.Content)
			}
		}()

		fmt.Printf("\n")
		fmt.Printf("  ██╗     ███████╗████████╗██╗  ██╗███████╗\n")
		fmt.Printf("  ██║     ██╔════╝╚══██╔══╝██║  ██║██╔════╝\n")
		fmt.Printf("  ██║     █████╗     ██║   ███████║█████╗  \n")
		fmt.Printf("  ██║     ██╔══╝     ██║   ██╔══██║██╔══╝  \n")
		fmt.Printf("  ███████╗███████╗   ██║   ██║  ██║███████╗\n")
		fmt.Printf("  ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝\n")
		fmt.Printf("                    the network that forgets\n\n")
		fmt.Printf("  Identity  : %s\n", kp.PublicKeyHex())
		fmt.Printf("  Listening : %s\n", listen)
		fmt.Printf("  SOCKS5    : %s  ← set this in your browser\n", proxyAddr)
		fmt.Printf("  Data      : %s\n", dataDir)
		if exposePort > 0 {
			fmt.Printf("  Exposing  : localhost:%d  ← hidden service active\n", exposePort)
		}
		if len(bootstrapList) > 0 {
			fmt.Printf("  Bootstrap : %s\n", strings.Join(bootstrapList, ", "))
		}
		fmt.Printf("\n  Commands (in another terminal):\n")
		fmt.Printf("    lethe register <name>            — register your name\n")
		fmt.Printf("    lethe send <name|key> <message>  — send a message\n")
		fmt.Printf("    lethe status                     — show node status\n\n")

		// Interactive console
		fmt.Print("> ")
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					fmt.Print("> ")
					continue
				}
				parts := strings.SplitN(line, " ", 3)
				switch parts[0] {
				case "send":
					if len(parts) < 3 {
						fmt.Println("usage: send <name|key> <message>")
					} else {
						recipient := parts[1]
						// Try name lookup first
						if key, ok := n.LookupName(recipient); ok {
							recipient = key
						}
						if err := n.Send(recipient, parts[2]); err != nil {
							fmt.Printf("error: %v\n", err)
						} else {
							fmt.Printf("✓ queued\n")
						}
					}
				case "register":
					if len(parts) < 2 {
						fmt.Println("usage: register <name>")
					} else {
						if err := n.RegisterName(parts[1]); err != nil {
							fmt.Printf("error: %v\n", err)
						} else {
							fmt.Printf("✓ registered '%s'\n", parts[1])
						}
					}
				case "status":
					fmt.Printf("peers: %d\n", tr.PeerCount())
				default:
					fmt.Printf("unknown command: %s\n", parts[0])
				}
				fmt.Print("> ")
			}
		}()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Println("\nShutting down. Forgetting everything.")
		return nil
	},
}

// ─── send ────────────────────────────────────────────────────────────────────

var sendCmd = &cobra.Command{
	Use:   "send <name|pubkey> <message>",
	Short: "Send an anonymous message",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		dataDir, _ := cmd.Flags().GetString("data")

		kp, err := crypto.LoadKeyPair(filepath.Join(dataDir, "identity.json"))
		if err != nil {
			return fmt.Errorf("no identity: run 'lethe keygen' first")
		}

		dir, err := directory.New(dataDir)
		if err != nil {
			return fmt.Errorf("open directory: %w", err)
		}
		defer dir.Close()

		recipient := args[0]
		message := strings.Join(args[1:], " ")

		// Try name resolution
		if entry := dir.Lookup(recipient); entry != nil {
			recipient = entry.EncPub
		}

		// Validate it's a hex key
		if _, err := crypto.PubKeyFromHex(recipient); err != nil {
			return fmt.Errorf("unknown recipient %q — not a valid key and not in directory", args[0])
		}

		fmt.Printf("Recipient : %s\n", recipient[:16]+"...")
		fmt.Printf("Sender    : %s\n", kp.PublicKeyHex()[:16]+"...")
		fmt.Printf("Message   : %s\n\n", message)
		fmt.Println("Note: connect to a running daemon to transmit ('lethe daemon').")
		fmt.Println("This command will integrate with the daemon IPC socket in v0.2.")
		return nil
	},
}

// ─── register ────────────────────────────────────────────────────────────────

var registerCmd = &cobra.Command{
	Use:   "register <name>",
	Short: "Register a human-readable name for your identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dataDir, _ := cmd.Flags().GetString("data")
		name := args[0]

		kp, err := crypto.LoadKeyPair(filepath.Join(dataDir, "identity.json"))
		if err != nil {
			return fmt.Errorf("no identity: run 'lethe keygen' first")
		}

		dir, err := directory.New(dataDir)
		if err != nil {
			return err
		}
		defer dir.Close()

		e := &directory.Entry{
			Name:    name,
			EncPub:  kp.PublicKeyHex(),
			SignPub: fmt.Sprintf("%x", kp.SignPub),
		}
		if err := e.Sign(kp.SignPriv); err != nil {
			return err
		}
		if err := dir.Add(e); err != nil {
			return err
		}

		fmt.Printf("✓ Registered '%s' → %s\n", name, kp.PublicKeyHex())
		fmt.Println("Start the daemon to broadcast this registration to the network.")
		return nil
	},
}

// ─── status ──────────────────────────────────────────────────────────────────

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show node identity and directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		dataDir, _ := cmd.Flags().GetString("data")
		identityPath := filepath.Join(dataDir, "identity.json")

		kp, err := crypto.LoadKeyPair(identityPath)
		if err != nil {
			fmt.Println("No identity found. Run 'lethe keygen' to create one.")
			return nil
		}

		dir, err := directory.New(dataDir)
		if err != nil {
			return err
		}
		defer dir.Close()

		fmt.Printf("Identity : %s\n", kp.PublicKeyHex())
		entries := dir.All()
		fmt.Printf("Directory: %d entries\n", len(entries))
		for _, e := range entries {
			fmt.Printf("  %-20s %s\n", e.Name, e.EncPub[:16]+"...")
		}
		return nil
	},
}

func init() {
	dd := defaultDataDir()

	for _, cmd := range []*cobra.Command{keygenCmd, daemonCmd, sendCmd, registerCmd, statusCmd} {
		cmd.Flags().String("data", dd, "Data directory (~/.lethe)")
	}

	daemonCmd.Flags().String("listen", "0.0.0.0:4242", "TCP listen address for peer connections")
	daemonCmd.Flags().String("proxy", "127.0.0.1:1080", "SOCKS5 proxy address")
	daemonCmd.Flags().StringSlice("bootstrap", []string{}, "Bootstrap peer addresses (host:port)")
	daemonCmd.Flags().Int("expose", 0, "Local port to expose as a hidden service (0 = not hosting)")

	rootCmd.AddCommand(keygenCmd, daemonCmd, sendCmd, registerCmd, statusCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
