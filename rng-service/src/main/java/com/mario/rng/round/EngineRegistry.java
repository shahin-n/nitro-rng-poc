package com.mario.rng.round;

import com.mario.rng.round.engines.DiceEngine;
import com.mario.rng.round.engines.MinesEngine;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Maps game_type -> {@link GameEngine}. Add a game by registering one here; nothing else changes. */
public final class EngineRegistry {

    private final Map<String, GameEngine> engines = new ConcurrentHashMap<>();

    public EngineRegistry() {
        register(new MinesEngine());
        register(new DiceEngine());
    }

    public void register(GameEngine engine) {
        engines.put(engine.gameType(), engine);
    }

    public GameEngine get(String gameType) {
        GameEngine e = engines.get(gameType);
        if (e == null) {
            throw new IllegalArgumentException("unknown game_type: " + gameType);
        }
        return e;
    }
}
