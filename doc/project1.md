Design Document for Project 1: Threads
======================================

## Group Members

* ლაშა ბუხნიკაშვილი <lbukh16@freeuni.edu.ge>
* ზაურ მეშველიანი <zmesh15@freeuni.edu.ge>
* ბაკურ ცუცხაშვილი <btsut16@freeuni.edu.ge>
* ლუკა ჭუმბურიძე <lchum16@freeuni.edu.ge>


# Efficient Alarm Clock
დავალების ამ ნაწილში მოითხოვებოდა `timer_sleep` ფუნქციის იმპლემენტირება
```c 
void timer_sleep (int64_t ticks);
```
ამ ფუნქციის გამოძახებისას ნაკადი `ticks` რაოდენობის თიქის განმავობაში პროცესორს რესურსს აღარ უნდა სთხოვდეს.

#### ამის მისაღწევად დავამეტეთ:
* თითოეულ ნაკადს `awake_time` წევრი, სადაც ინახება tick რომელზეც სრედის გაღვიძება უნდა მოხდეს. თუ სრედი დაძინებული არაა მაშინ ეს მნიშვნელობა `-1`-ია.
* კერნელში ჩავამატეთ ლისტი `sleeping_list`, რომელიც ინახავს დაძინებულ სრედებს.


`timer_sleep` ფუნქციაში ვითვლით გაღვიძების დროს და ნაკადს ვამატებთ `sleeping_list`-ში. ხოლო შემდეგ, ყოველთ თიქზე, `timer_interrupt`-ში ხდება იმ ნაკადების გაღვიძება რომლის დროც მოვიდა.

#### გვქონდა ორი ვარიანტი:
* სიაში კონსტანტა დროში ჩაგვემატებინა და შემდეგ ყოველ tick-ზე წრფივ დროში შეგვემოწმებინა გასაღვიძებელი ნაკადები.
* ლისტში ჩამატება ![f1] დროში და შემდეგ გასაღვიძებელი ნაკადები კონსტანტა დროში ამოგვეღო.

[f1]: http://chart.apis.google.com/chart?cht=tx&chl=O(nlog(n))&chf=bg,s,FFFFFF00

რადგან თიქის ინტერაფთი გაცილებით ხშირად ხდება, ვიდრე `timer_sleep`-ის გამოძახება, ამიტომ მეორე ვარიანტი ვარჩიეთ და `sleeping_list` სიაში ნაკადებს `awake_time`-ის ზრდის მიხედვით ვინახავთ. ხოლო ყოველი თიქის ინთერაფთის დროს მხოლოდ მანამდე ვაგრძელებთ სიაზე გადაყოლას, სანამ კიდევ არიან ნაკადები გასაღვიძებელი.


# Priority Scheduler
თავდაპირველად განვიხილოთ უშუალოდ **Priority Scheduler** შემდეგ კი **Priority Donation**.

პირველი დავალების მსგავსად აქაც ორი ვარიანტი გვქონდა:
* *ready_list*-ის დალაგებულად შენახვა და ![f2] დროში ამოღება
* სიაში პირდაპირ ჩაყრა და ![f3] დროში ამოღება.

*ავირჩიეთ პირველი.*

პირველ რიგში, რაც აშკარაა *Scheduler*-მა უნდა გაითვალისწინოს ნაკადები პრიორიტეტები და ნაცვლად იმისა, რომ `next_thread_to_run()` ფუნქციამ *ready_list*-დან უბრალოდ პირველი ნაკადი აირჩიოს, საჭიროა ამ სიაში აირჩიოს მაქსიმალური პრიორიტეტის მქონე ნაკადი. საჭირო იყო ნაკადების პრიორიტეტებით შედარების ფუნქციის იმპლემენტაცია (`thread_priority_cmp()`).

*Scheduler*- ის მსგავსად ნაკადების პრიორიტეტების გათვალისწინება საჭირო იყო *lock*-ებში, *conditional variable*-ებსა და *semaphore*-ებში. იმის გამო, რომ ამ პროექტში *lock* პირდაპირ *semaphore*-ითაა იმპლემენტირებული, *lock*-ში ცალკე პრიორიტეტების გათვალისწინება აღარაა საჭირო. აქაც `next_thread_to_run()`-ის მსგავსად `list_max()` ფუნქციას ვიყენებთ, რომელსაც უკვე დაწერილ `thread_priority_cmp()` ფუნქციას გადავცემთ.

იმის გამო, რომ ჩვენი **Priority Scheduler** უნდა ყოფილიყო *pre-emptive*, სემაფორაში ნაკადის განბლოკვის შემდეგ საჭირო იყო `thread_yield`-ის გამოძახება.

რაც შეეხება [**მარია აზამასცევას**](https://www.youtube.com/watch?v=PA4JYDQGJ6k) *(Priority Donation)*. ნაკადებს შორის პრიორიტეტების გადაცემისთვის გამოვიყენეთ შემდეგი სტრუქტურა:

*  ყველა lock,  `elem` ველში, ინახავს იმ lock-ების სიას, რომელიც მასთან ერთად აღებული აქვს რომელიმე ნაკადს.
* ყველა ნაკადი `blocked_by` ველში ინახავს იმ lock-ის მისამართს, რომელმაც შეაჩერა ეს ნაკადი (თუ ნაკადი არ შეჩერებულა `NULL`)
* ყველა ნაკადი `acquired_locks` ველში ინახავს აღებული lock-ების სიას.
* ყველა ნაკადს  `pure_priority` ველი, სადაც ვინახავთ იმ პრიორიტეტს რომელიც ნაკადს donation-ების გარეშე აქვს. არსებული `priority` ველი კი ინახავს რეალურ პრიორიტეტს, რომელიც შედარებისას გამოიყენება.

Priority Donation-ისთვის დავწერეთ `donate_priority()` ფუნქცია, რომელიც რეკურსიულად მიუყვება იმ lock-იდან, რომელმაც ეს ნაკადი დაბლოკა ირჩევს მის `holder` ნაკადს, უცვლის პრიორიტეტს და გადადის მის `blocked_by` ლოქზე. ა.შ რეკურსიულად მანამ, სანამ არ მივალთ მუშა ნაკადამდე, ანუ 
```c
thread->blocked_by != NULL
```
პრიორიტეტის ირიბად განახლებისთვის ვიყენებთ `thread_update_prior()` ფუნქციას

[f2]: http://chart.apis.google.com/chart?cht=tx&chl=O(1)&chf=bg,s,FFFFFF00
[f3]: http://chart.apis.google.com/chart?cht=tx&chl=O(n)&chf=bg,s,FFFFFF00


#  Multi-level Feedback Queue Scheduler (MLFQS)
ამ ტიპის scheduler-ში თითეული Thread-ისთვის პრიორიტეტი, ყოველ მე-4 ***Tick***-ზე შემდეგი ფორმულით გამოითვლება:
```
priority = PRI_MAX − (recent_cpu/4) − (nice × 2)
```
 
იმისთვის რომ ყველა Thread-ისთვის ყოველ მე-4 Tick-ზე შეგვეცვალა ეს პრიორიტეტი, thread_foreach მეთოდს გადავცემთ ***mlfq_priority_update*** მეთოდს:
```c
void mlfq_priority_update(struct thread *t)
``` 
 რომელიც გამოიძახებს და შეცვლის პრიორიტეტს ამ მეთოდით, განახლებული recent_cpu და nice მნიშვნელობითურთ.

***recent_cpu*** გამოითვლება შემდეგი ფორმულით:
```
 recent_cpu = (2 × load_avg)/(2 × load_avg + 1) × recent_cpu + nice
 ```
 ეს მნიშვნელობა ყველა Thread-თვის სათითაოდ უნდა დაითვალოს, ამიტომ მასაც  thread_foreach მეთოდს გადავცემთ, მას შემდეგ რაც ***load_avg*** მნიშვნელობა იქნება დათვლილი.

***load_avg*** მნიშვნელობა გამოითვლება ფორმულით:
```
load_avg = (59/60) × load_avg + (1/60) × ready_threads
```
რომელიც გლობალურად უნდა დაითვალოს წამში TIMER_FREQ-ჯერ.

# 2.1.2 Additional Questions

### Test
```c
void test(void)
{
    thread_set_priority (PRI_DEFAULT-2);
    struct semaphore sema;
    sema_init(&sema, 0);
    thread_create("test_thread", PRI_DEFAULT, test_thread_func, &sema);    
    thread_create("second_test_thread", PRI_DEFAULT+1, second_test_thread_func, &sema);    
    thread_create("just_thread", PRI_DEFAULT-1, just_thread_func, NULL);
    msg("in main");
    sema_up(&sema);
    sema_up(&sema);
    msg("main thread finished");
}

void test_thread_func(void *s)
{
    msg("test_thread started");
    struct semaphore *sema = s;
    sema_down (sema);
    msg("test_thread after sema_down");
}

void second_test_thread_func(void *s)
{
    msg("second_test_thread started");
    struct semaphore *sema = s;
    sema_down (sema);
    msg("second_test_thread after sema_down");
}

void just_thread_func(void *s)
{
    msg("just_thread printing just text");
}
```
ამ ტესტზე სწორი პასუხია:
```
test_thread started
second_test_thread started
in main
second_test_thread after sema_down
test_thread after sema_down
just_thread printing just text
main thread finished
```
აღწერილი იმპლემენაცია კი გამოიტანს შემდეგს:
```c
test_thread started
second_test_thread started
just_thread printing just test
in_main
test_thread after sema_down
second_test_thread after sema_down
main thread finished
```

როგორც ვხედავთ აღწერილმა იმპლემენტაციამ სემაფორის მომატებისას არც დაბლოკილი ნაკადების პრიორიტეტები გაითვალისწინა (test_thread უფრო მალე განიბლოკა ვიდრე second_test_thread) და არც priority_donation-ს მიაქცია ყურადღება (just_thread გაუშვა მაშინ, როდესაც main უნდა გაეშვა).