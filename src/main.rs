use symex::{
    elf_util::VisualPathResult,
    general_assembly::{project::MemoryHookAddress, state::GAState, Result as GAResult, RunConfig},
    run_elf::run_elf,
    smt::DExpr,
};

use srp::common::{Task, Trace, Tasks, TaskResult, TasksResult};

// This example show how hooks can be used to get at which cycle a resource is locked and unlocked in a simple
// RTIC application. To keep in mind is that cycles are added after the instruction is executed and the hook
// is run during instruction execution. Therefore care needs to be taken to measure the critical section
// correctly.

// To run the example first build the "rtic_simple_resourse" in armv6-m-examples by doing:
// cd armv6-m-examples
// cargo build --release --example rtic_simple_resourse
// cd ..
//
// Then run the analysis by: cargo run -p wcet-analasis-examples --release --example wcet_resource_times

fn make_trace(start: usize, end: usize, laps: &[(usize, String)], id: String) -> Trace {
    let mut inner = vec![];

    let mut current = "";
    let mut inner_start = 0;
    let mut in_inner = false;
    let mut start_i = 0;
    for i in 0..laps.len() {
        if !in_inner {
            current = &laps[i].1;
            inner_start = laps[i].0;
            start_i = i;
            in_inner = true
        } else {
            if current == &laps[i].1 {
                inner.push(make_trace(
                    inner_start,
                    laps[i].0,
                    &laps[(start_i + 1)..i],
                    laps[i].1.to_owned(),
                ));
                in_inner = false;
            }
        }
    }

    Trace {
        id,
        start: start as u32,
        end: end as u32,
        inner,
    }
}

fn create_task(symex_result: &VisualPathResult, task: &InputTask) -> Task {
    let trace = make_trace(0, symex_result.max_cycles, &symex_result.cycle_laps, task.name.to_owned());
    Task { id: task.name.to_owned(), prio: task.priority as u8, deadline: task.deadline, inter_arrival: task.interarival, trace }
}

fn analyze_tasks(task: &InputTask, path: &str) -> Vec<VisualPathResult> {
    // path to the elf file to analyse.
    let path_to_elf_file = path;
    // name of the task in the elf file (same as associated interrupt vector for HW tasks).
    let function_name = &task.interrupt;

    // Hook to run when the interrupt mask is reset (looked).
    let lock_hook: fn(state: &mut GAState, addr: u64, value: DExpr, bits: u32) -> GAResult<()> =
        |state, _addr, value, _bits| {
            // save the current cycle count to the laps vector.
            let val = value.get_constant().unwrap().to_string();
            state.cycle_laps.push((state.cycle_count, val));
            Ok(())
        };

    // Hook to run when the interrupt mask is set (unlocked).
    let unlock_hook: fn(state: &mut GAState, addr: u64, value: DExpr, bits: u32) -> GAResult<()> =
        |state, _addr, value, _bits| {
            // save the current cycle count to the laps vector.
            let val = value.get_constant().unwrap().to_string();
            let current_instruction_cycle_count =
                match state.current_instruction.as_ref().unwrap().max_cycle {
                    symex::general_assembly::instruction::CycleCount::Value(v) => v,
                    symex::general_assembly::instruction::CycleCount::Function(f) => f(state),
                };

            // add the current instruction to the cycle count to compensate for cycles added after instruction completed
            let cycle_count = state.cycle_count + current_instruction_cycle_count;
            state.cycle_laps.push((cycle_count, val));
            Ok(())
        };

    // create a run configuration with the hooks associated with the correct addresses.
    let config = RunConfig {
        pc_hooks: vec![],
        register_read_hooks: vec![],
        register_write_hooks: vec![],
        memory_write_hooks: vec![
            (MemoryHookAddress::Single(0xe000e100), unlock_hook),
            (MemoryHookAddress::Single(0xe000e180), lock_hook),
        ],
        memory_read_hooks: vec![],
        show_path_results: false,
    };

    // run the symbolic execution
    run_elf(path_to_elf_file, function_name, config).unwrap()
}

struct InputTask {
    name: String,
    interrupt: String,
    priority: u32,
    deadline: u32,
    interarival: u32,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
enum RP2040Interrupts {
    TIMER_IRQ_0,
    TIMER_IRQ_1,
    TIMER_IRQ_2,
    TIMER_IRQ_3,
    PWM_IRQ_WRAP,
    USBCTRL_IRQ,
    XIP_IRQ,
    PIO0_IRQ_0,
    PIO0_IRQ_1,
    PIO1_IRQ_0,
    PIO1_IRQ_1,
    DMA_IRQ_0,
    DMA_IRQ_1,
    IO_IRQ_BANK0,
    IO_IRQ_QSPI,
    SIO_IRQ_PROC0,
    SIO_IRQ_PROC1,
    CLOCKS_IRQ,
    SPI0_IRQ,
    SPI1_IRQ,
    UART0_IRQ,
    UART1_IRQ,
    ADC_IRQ_FIFO,
    I2C0_IRQ,
    I2C1_IRQ,
    RTC_IRQ,
}

impl TryFrom<u8> for RP2040Interrupts {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<RP2040Interrupts, &'static str> {
        match value {
            0 => Ok(RP2040Interrupts::TIMER_IRQ_0),
            1 => Ok(RP2040Interrupts::TIMER_IRQ_1),
            2 => Ok(RP2040Interrupts::TIMER_IRQ_2),
            3 => Ok(RP2040Interrupts::TIMER_IRQ_3),
            4 => Ok(RP2040Interrupts::PWM_IRQ_WRAP),
            5 => Ok(RP2040Interrupts::USBCTRL_IRQ),
            6 => Ok(RP2040Interrupts::XIP_IRQ),
            7 => Ok(RP2040Interrupts::PIO0_IRQ_0),
            8 => Ok(RP2040Interrupts::PIO0_IRQ_1),
            9 => Ok(RP2040Interrupts::PIO1_IRQ_0),
            10 => Ok(RP2040Interrupts::PIO1_IRQ_1),
            11 => Ok(RP2040Interrupts::DMA_IRQ_0),
            12 => Ok(RP2040Interrupts::DMA_IRQ_1),
            13 => Ok(RP2040Interrupts::IO_IRQ_BANK0),
            14 => Ok(RP2040Interrupts::IO_IRQ_QSPI),
            15 => Ok(RP2040Interrupts::SIO_IRQ_PROC0),
            16 => Ok(RP2040Interrupts::SIO_IRQ_PROC1),
            17 => Ok(RP2040Interrupts::CLOCKS_IRQ),
            18 => Ok(RP2040Interrupts::SPI0_IRQ),
            19 => Ok(RP2040Interrupts::SPI1_IRQ),
            20 => Ok(RP2040Interrupts::UART0_IRQ),
            21 => Ok(RP2040Interrupts::UART1_IRQ),
            22 => Ok(RP2040Interrupts::ADC_IRQ_FIFO),
            23 => Ok(RP2040Interrupts::I2C0_IRQ),
            24 => Ok(RP2040Interrupts::I2C1_IRQ),
            25 => Ok(RP2040Interrupts::RTC_IRQ),
            _ => Err("Invalid"),
        }
    }
}

fn irq_from_bit_vector(bit_vector: u32) -> Vec<RP2040Interrupts> {
    let mut ret = vec![];

    for i in 0..32 {
        let mask = 1 << i;
        if mask & bit_vector != 0 {
            ret.push(i.try_into().expect("error"));
        }
    }

    ret
}

fn get_task_list() -> Vec<InputTask> {
    let mut list = vec![];
    list.push(InputTask {
        name: "button_handler".to_owned(),
        interrupt: "IO_IRQ_BANK0".to_owned(),
        priority: 2,
        deadline: 125000,
        interarival: 125000,
    });
    list.push(InputTask {
        name: "debounce_button".to_owned(),
        interrupt: "TIMER_IRQ_1".to_owned(),
        priority: 3,
        deadline: 1230000,
        interarival: 37500000,
    });
    list.push(InputTask {
        name: "alarm0_handler".to_owned(),
        interrupt: "TIMER_IRQ_0".to_owned(),
        priority: 1,
        interarival: 62500000,
        deadline: 1250000,
    });
    list.push(InputTask {
        name: "alarm2_handler".to_owned(),
        interrupt: "TIMER_IRQ_2".to_owned(),
        priority: 4,
        interarival: 125000000,
        deadline: 125000,
    });
    list
}


fn main() {
    println!("Simple WCET analasis");

    let task_list = get_task_list();

    let path_to_elf_file = "test_bin/rtic_full_example";

    let mut tasks = vec![];

    for task in &task_list {
        let result = analyze_tasks(task, path_to_elf_file);
        let mut tasks_of_task = vec![];
        for r in result {
            let t = create_task(&r, task);
            tasks_of_task.push(t);
        }
        tasks.push(tasks_of_task);
    }

    let mut expected = 1;
    for t in &tasks {
        expected *= t.len();
    }

    println!("expected: {}", expected);
    
    let list_to_test = get_all_sets(&tasks[..]);

    println!("gotten: {}", list_to_test.len());

    for (i, list) in list_to_test.iter().enumerate() {
        print!("list {i}: [");
        for item in list {
            print!("{}, ", item.id);
        }
        println!("]")
    }

    let mut list_of_task_results = vec![];

    let mut max_utilization: f32 = 0.0;
    for tasks in list_to_test {
        let tasks = Tasks(tasks);
        let result = tasks.response_time();
        max_utilization = max_utilization.max(tasks.total_utilization());
        list_of_task_results.push(result);
    }
    
    println!("Max utilization: {}", max_utilization);
    let worst_result = find_worst(list_of_task_results);

    for result in worst_result.0 {
        print!("Task: {}, max response time: {}, deadline: {}, ", result.task.id, result.response_time.unwrap(), result.task.deadline);
        if result.response_time.unwrap() <= result.task.deadline {
            println!("[SUCCESS]");
        } else {
            println!("[FAIL]");
        }
    }

}

fn cheap_clone(input: &TaskResult) -> TaskResult {
    TaskResult {
        task: input.task.to_owned(),
        response_time: input.response_time,
        wcet: input.wcet,
        blocking: input.blocking,
        interference: input.interference,
    }
}

fn find_worst(list_of_task_results: Vec<TasksResult>) -> TasksResult {

    let mut worst_by_response_time = vec![];
    for i in 0..list_of_task_results[0].0.len() {
        let mut current_worst: Option<TaskResult> = None;
        for task in &list_of_task_results {
            match &current_worst {
                Some(v) => {
                    if v.response_time < task.0[i].response_time {
                        current_worst = Some(cheap_clone(&task.0[i]))
                    }
                },
                None => {
                    current_worst = Some(cheap_clone(&task.0[i]))
                },
            }
        }
        worst_by_response_time.push(current_worst.unwrap())
    }

    TasksResult(worst_by_response_time)
}

fn get_all_sets(tasks: &[Vec<Task>]) -> Vec<Vec<Task>> {
    if tasks.len() == 1 {
        let mut ret = vec![];
        for t in &tasks[0] {
            ret.push(vec![t.to_owned()])
        }
        ret
    } else {
        let mut ret = vec![];
        for t in &tasks[0] {
            let r = get_all_sets(&tasks[1..]);
            for mut ta in r {
                ta.push(t.clone());
                ret.push(ta)
            }
        }
        ret
    }
}
