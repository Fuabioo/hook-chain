package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Fuabioo/hook-chain/internal/audit"
	_ "modernc.org/sqlite"
)

func openAuditDB(cmd *cobra.Command) (*sql.DB, error) {
	dbPath, err := cmd.Flags().GetString("db")
	if err != nil || dbPath == "" {
		dbPath = audit.DefaultDBPath()
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open audit db %q: %w", dbPath, err)
	}
	return db, nil
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Query the audit log",
	}
	cmd.PersistentFlags().String("db", "", "path to audit database (default: auto-detected)")
	cmd.AddCommand(
		newAuditListCmd(),
		newAuditShowCmd(),
		newAuditTailCmd(),
		newAuditPruneCmd(),
		newAuditStatsCmd(),
		newAuditDBPathCmd(),
	)
	return cmd
}

func newAuditListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List chain executions",
		RunE:  runAuditList,
	}
	cmd.Flags().Int("limit", 20, "maximum number of entries")
	cmd.Flags().Int("offset", 0, "skip N entries")
	cmd.Flags().String("event", "", "filter by event name")
	cmd.Flags().String("outcome", "", "filter by outcome")
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

func runAuditList(cmd *cobra.Command, _ []string) error {
	db, err := openAuditDB(cmd)
	if err != nil {
		return err
	}
	defer db.Close()

	limit, err := cmd.Flags().GetInt("limit")
	if err != nil {
		return fmt.Errorf("invalid --limit: %w", err)
	}
	offset, err := cmd.Flags().GetInt("offset")
	if err != nil {
		return fmt.Errorf("invalid --offset: %w", err)
	}
	event, err := cmd.Flags().GetString("event")
	if err != nil {
		return fmt.Errorf("invalid --event: %w", err)
	}
	outcome, err := cmd.Flags().GetString("outcome")
	if err != nil {
		return fmt.Errorf("invalid --outcome: %w", err)
	}
	asJSON, err := cmd.Flags().GetBool("json")
	if err != nil {
		return fmt.Errorf("invalid --json: %w", err)
	}

	chains, err := audit.ListChains(db, limit, offset, event, outcome)
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}

	if asJSON {
		return printJSON(chains)
	}
	printChainTable(chains)
	return nil
}

func newAuditShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show details of a chain execution",
		Args:  cobra.ExactArgs(1),
		RunE:  runAuditShow,
	}
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

func runAuditShow(cmd *cobra.Command, args []string) error {
	db, err := openAuditDB(cmd)
	if err != nil {
		return err
	}
	defer db.Close()

	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chain ID %q: %w", args[0], err)
	}

	asJSON, err := cmd.Flags().GetBool("json")
	if err != nil {
		return fmt.Errorf("invalid --json: %w", err)
	}

	chain, err := audit.GetChain(db, id)
	if err != nil {
		return fmt.Errorf("get chain %d: %w", id, err)
	}

	if asJSON {
		return printJSON(chain)
	}

	fmt.Printf("Chain #%d\n", chain.ID)
	fmt.Printf("  Timestamp:  %s\n", chain.Timestamp.Format(time.RFC3339))
	fmt.Printf("  Event:      %s\n", chain.EventName)
	fmt.Printf("  Tool:       %s\n", chain.ToolName)
	fmt.Printf("  Chain Len:  %d\n", chain.ChainLen)
	fmt.Printf("  Outcome:    %s\n", chain.Outcome)
	fmt.Printf("  Reason:     %s\n", chain.Reason)
	fmt.Printf("  Duration:   %dms\n", chain.DurationMs)
	fmt.Printf("  Session:    %s\n", chain.SessionID)

	if len(chain.Hooks) > 0 {
		fmt.Printf("\n  Hook Results:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  IDX\tNAME\tEXIT\tOUTCOME\tDURATION\tSTDERR")
		for _, h := range chain.Hooks {
			stderr := h.Stderr
			if len(stderr) > 60 {
				stderr = stderr[:57] + "..."
			}
			fmt.Fprintf(w, "  %d\t%s\t%d\t%s\t%dms\t%s\n",
				h.HookIndex, h.HookName, h.ExitCode, h.Outcome, h.DurationMs, stderr)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("flush tabwriter: %w", err)
		}
	}

	return nil
}

func newAuditTailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show last N chain executions",
		RunE:  runAuditTail,
	}
	cmd.Flags().Int("n", 10, "number of entries")
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

func runAuditTail(cmd *cobra.Command, _ []string) error {
	db, err := openAuditDB(cmd)
	if err != nil {
		return err
	}
	defer db.Close()

	n, err := cmd.Flags().GetInt("n")
	if err != nil {
		return fmt.Errorf("invalid --n: %w", err)
	}
	asJSON, err := cmd.Flags().GetBool("json")
	if err != nil {
		return fmt.Errorf("invalid --json: %w", err)
	}

	chains, err := audit.Tail(db, n)
	if err != nil {
		return fmt.Errorf("tail: %w", err)
	}

	if asJSON {
		return printJSON(chains)
	}
	printChainTable(chains)
	return nil
}

func newAuditPruneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete old audit entries",
		RunE:  runAuditPrune,
	}
	cmd.Flags().String("older-than", "", "delete entries older than duration (e.g., 7d, 24h, 30d)")
	if err := cmd.MarkFlagRequired("older-than"); err != nil {
		panic(fmt.Sprintf("mark --older-than required: %v", err))
	}
	return cmd
}

func runAuditPrune(cmd *cobra.Command, _ []string) error {
	db, err := openAuditDB(cmd)
	if err != nil {
		return err
	}
	defer db.Close()

	olderThanStr, err := cmd.Flags().GetString("older-than")
	if err != nil {
		return fmt.Errorf("invalid --older-than: %w", err)
	}

	dur, err := parseDuration(olderThanStr)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", olderThanStr, err)
	}

	count, err := audit.Prune(db, dur)
	if err != nil {
		return fmt.Errorf("prune: %w", err)
	}

	fmt.Printf("Pruned %d chain execution(s).\n", count)
	return nil
}

func newAuditStatsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show audit statistics",
		RunE:  runAuditStats,
	}
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

func runAuditStats(cmd *cobra.Command, _ []string) error {
	db, err := openAuditDB(cmd)
	if err != nil {
		return err
	}
	defer db.Close()

	asJSON, err := cmd.Flags().GetBool("json")
	if err != nil {
		return fmt.Errorf("invalid --json: %w", err)
	}

	stats, err := audit.Stats(db)
	if err != nil {
		return fmt.Errorf("stats: %w", err)
	}

	if asJSON {
		return printJSON(stats)
	}

	fmt.Printf("Total chains:   %d\n", stats.TotalChains)
	fmt.Printf("Avg duration:   %.1fms\n", stats.AvgDurationMs)

	if stats.TotalChains > 0 {
		fmt.Printf("Oldest entry:   %s\n", stats.OldestEntry.Format(time.RFC3339))
		fmt.Printf("Newest entry:   %s\n", stats.NewestEntry.Format(time.RFC3339))
	}

	if len(stats.CountByOutcome) > 0 {
		fmt.Printf("\nBy outcome:\n")
		for outcome, count := range stats.CountByOutcome {
			fmt.Printf("  %-10s %d\n", outcome, count)
		}
	}

	return nil
}

func newAuditDBPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "db-path",
		Short: "Print the audit database path",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(audit.DefaultDBPath())
		},
	}
}

// printChainTable outputs chain executions in a tabwriter table.
func printChainTable(chains []audit.ChainExecution) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTIMESTAMP\tEVENT\tTOOL\tHOOKS\tOUTCOME\tDURATION")
	for _, c := range chains {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\t%dms\n",
			c.ID,
			c.Timestamp.Format(time.RFC3339),
			c.EventName,
			c.ToolName,
			c.ChainLen,
			c.Outcome,
			c.DurationMs,
		)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "hook-chain: flush table: %v\n", err)
	}
}

// printJSON marshals v as indented JSON and writes to stdout.
func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// parseDuration parses a duration string supporting "Nd" (days) and "Nh" (hours) formats,
// in addition to Go's standard time.Duration formats.
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}

	// Handle "Nd" (days) format.
	if strings.HasSuffix(s, "d") {
		numStr := strings.TrimSuffix(s, "d")
		n, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days %q: %w", numStr, err)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}

	// Handle "Nh" (hours) format.
	if strings.HasSuffix(s, "h") {
		numStr := strings.TrimSuffix(s, "h")
		n, err := strconv.Atoi(numStr)
		if err != nil {
			// Fall through to time.ParseDuration which handles "1h30m" etc.
			return time.ParseDuration(s)
		}
		return time.Duration(n) * time.Hour, nil
	}

	// Fall back to Go's standard duration parsing.
	return time.ParseDuration(s)
}
