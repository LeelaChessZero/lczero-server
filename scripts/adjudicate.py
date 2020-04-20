#!/usr/bin/env python3

# This file is part of Leela Chess.
# Copyright (C) 2018 Leela Chess authors
#
# Leela Chess is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Leela Chess is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Leela Chess. If not, see <http://www.gnu.org/licenses/>.

import argparse
import chess
import chess.pgn
import chess.syzygy
import os

def get_configuration():
    """
    Returns a populated configuration
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--pgn', type=str, default='',
                        help="file_to_adjudicate", required=True)
    parser.add_argument('--syzygy', type=str, default='',
                        help="Syzygy directories", required=True)
    parser.add_argument('--output', type=str, default='',
                        help="Output pgn name", required=True)

    return parser.parse_args()


def main(cfg):
    syzygy_dirs = cfg.syzygy.split(os.pathsep)
    with chess.syzygy.open_tablebase(syzygy_dirs[0]) as tablebase:
        for i in range(len(syzygy_dirs)):
            if i == 0: continue
            tablebase.add_directory(syzygy_dirs[i])
        pgn = open(cfg.pgn)
        save_pgn = open(cfg.output, "w")
        saver = chess.pgn.FileExporter(save_pgn, columns=None)
        game = chess.pgn.read_game(pgn)
        while game != None:
            board = game.board()
            for move in game.mainline_moves():
                board.push(move)
                result = tablebase.get_wdl(board)
                if result != None:
                    if result == 0 or result == 1 or result == -1:
                        game.headers["Result"] = "1/2-1/2"
                    elif result == 2 and board.turn == chess.WHITE or result == -2 and board.turn == chess.BLACK:
                        game.headers["Result"] = "1-0"
                    else:
                        game.headers["Result"] = "0-1"
                    break
            game.accept(saver)
            game = chess.pgn.read_game(pgn)

if __name__ == "__main__":
    cfg = get_configuration()
    main(cfg)
