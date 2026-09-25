package billing

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const testCheckoutOrderID = "cs_purchase"

var testCheckoutNow = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)

func openBillingTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := os.Getenv("GLASSEQ_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("GLASSEQ_TEST_DATABASE_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.PingContext(context.Background()); err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	return database
}
