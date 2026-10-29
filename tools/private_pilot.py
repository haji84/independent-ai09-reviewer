"""Fixed reviewed dispatcher; no caller executable/provider/plugin selection."""
import pathlib
import sys

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import private_pilot

if __name__=='__main__':
    raise SystemExit(private_pilot.main())
