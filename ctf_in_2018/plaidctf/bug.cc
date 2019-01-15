// First determine if `map_function` can be called
  TNode<Object> map_function = args.GetOptionalArgumentValue(1);
  // If map_function is not undefined, then ensure it's callable else throw.
  {
    Label no_error(this), error(this);
    GotoIf(IsUndefined(map_function), &no_error);
    GotoIf(TaggedIsSmi(map_function), &error);
    Branch(IsCallable(map_function), &no_error, &error);
    BIND(&error);
    ThrowTypeError(context, MessageTemplate::kCalledNonCallable, map_function);
    BIND(&no_error);
  }
  ...
// See if [Symbol.iterator] is defined
IteratorBuiltinsAssembler iterator_assembler(state());
  Node* iterator_method =
      iterator_assembler.GetIteratorMethod(context, array_like);
  Branch(IsNullOrUndefined(iterator_method), &not_iterable, &iterable);

// can be iterated
BIND(&iterable);
    {
    ...
   // Verify that the method can be called, you can call to jump to next
   // Check that the method is callable.
    {
      Label get_method_not_callable(this, Label::kDeferred), next(this);
      GotoIf(TaggedIsSmi(iterator_method), &get_method_not_callable);
      GotoIfNot(IsCallable(iterator_method), &get_method_not_callable);
      Goto(&next);
      BIND(&get_method_not_callable);
      ThrowTypeError(context, MessageTemplate::kCalledNonCallable,
                     iterator_method);
      BIND(&next);
    }
    // Perform some initialization, here created an array of length 0
    // Construct the output array with empty length.
    array = ConstructArrayLike(context, args.GetReceiver());
    // Actually get the iterator and throw if the iterator method does not yield
    // one.
    IteratorRecord iterator_record =
        iterator_assembler.GetIterator(context, items, iterator_method);
    TNode<Context> native_context = LoadNativeContext(context);
    TNode<Object> fast_iterator_result_map =
        LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX);
    Goto(&loop);
    // Loop, enter the loop
    BIND(&loop);
    {
    ...
    BIND(&loop_done);
    {
      length = index;
      // Jump to finished when the loop is complete
      Goto(&finished);
    }
    }

  // Unable to iterate
  BIND(&not_iterable);
  {
  ...
  }


  BIND(&finished);
  // Finally set the length on the output and return it.
  GenerateSetLength(context, array.value(), length.value());
  args.PopAndReturn(array.value());