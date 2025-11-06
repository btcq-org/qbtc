package bitcoin

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func NewLevelDB(path string, compactOnInit bool) (*leveldb.DB, error) {
	// if path is empty, use in memory db
	if path == "" {
		memStorage := storage.NewMemStorage()
		return leveldb.Open(memStorage, nil)
	}

	// open the database (or create)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open level db %s: %w", path, err)
	}

	// compact the database if configured
	if compactOnInit {
		log.Info().Str("path", path).Msg("compacting leveldb...")
		err = db.CompactRange(util.Range{})
		if err != nil {
			return nil, fmt.Errorf("failed to compact level db %s: %w", path, err)
		}
		log.Info().Str("path", path).Msg("leveldb compacted")
	}

	return db, nil
}
