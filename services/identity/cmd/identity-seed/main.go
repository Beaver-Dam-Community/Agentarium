// Command identity-seed loads identity.registered_workloads from the install
// input file (services/identity/seed/registered_workloads.yaml). It validates
// the whole file first, then upserts every row in one transaction; it never
// deletes rows and never re-enables a disabled row.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/seed"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/store"
)

func main() {
	file := flag.String("file", "services/identity/seed/registered_workloads.yaml", "seed file")
	dbURL := flag.String("database-url", os.Getenv("IDENTITY_DATABASE_URL"), "PostgreSQL URL")
	check := flag.Bool("check", false, "validate the file only")
	flag.Parse()
	if err := run(*file, *dbURL, *check); err != nil {
		fmt.Fprintln(os.Stderr, "identity-seed:", err)
		os.Exit(1)
	}
}

func run(file, dbURL string, check bool) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	regs, err := seed.Parse(data)
	if err != nil {
		return err
	}
	if check {
		fmt.Printf("%d workloads valid\n", len(regs))
		return nil
	}
	if dbURL == "" {
		return fmt.Errorf("--database-url is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	ins, upd, err := store.Store{Pool: pool}.UpsertRegistrations(ctx, regs)
	if err != nil {
		return err
	}
	fmt.Printf("registered_workloads: %d inserted, %d updated\n", ins, upd)
	return nil
}
