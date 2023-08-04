import angr
import claripy
import sys

def symbolic_execution():
    p = angr.Project('test', auto_load_libs=False)

    known_good = p.loader.find_symbol('known_good').rebased_addr
    main = p.loader.find_symbol('main').rebased_addr
    tgt = p.loader.find_symbol('angr_target').rebased_addr
    input_buf = p.loader.find_symbol('input_buf').rebased_addr
    input_buf_sz = 80

    initial_state = p.factory.entry_state(addr=main)

    # Pedantic since we're not constraining any values...
    for i in range(input_buf_sz):
        ch = claripy.BVS(f'ch{i}', 8)
        initial_state.memory.store(input_buf+i, ch)

    sm = p.factory.simulation_manager(initial_state)

    sm.explore(find=tgt)

    goal_state = sm.found[0]
    input_data = goal_state.memory.load(input_buf, input_buf_sz)
    answer = goal_state.solver.eval(input_data, cast_to=bytes)
    print(answer)
    return 0

def main():
    return symbolic_execution()

if __name__ == '__main__':
    sys.exit(main())
