package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/juhokoskela/GlassEQServer/internal/billing"
	"github.com/juhokoskela/GlassEQServer/internal/config"
)

func checkStripeCatalog(ctx context.Context, logger *slog.Logger) error {
	settings, err := config.LoadStripeCatalog()
	if err != nil {
		return fmt.Errorf("load Stripe catalog configuration: %w", err)
	}
	client, err := billing.NewCheckoutClient(settings.SecretKey)
	if err != nil {
		return fmt.Errorf("create Stripe client: %w", err)
	}
	catalog := billing.CatalogSpec{
		Perpetual: billing.CatalogPrice{
			PriceID:   settings.PerpetualPriceID,
			ProductID: settings.PerpetualProductID,
		},
		Monthly: billing.CatalogPrice{
			PriceID:   settings.MonthlyPriceID,
			ProductID: settings.MonthlyProductID,
		},
	}
	if err := client.CheckCatalog(ctx, catalog); err != nil {
		return fmt.Errorf("validate Stripe catalog: %w", err)
	}
	logger.Info("Stripe catalog check passed")
	return nil
}
